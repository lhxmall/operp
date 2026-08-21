use crate::{BookError, Fill, MatchResult, Order};
use odex_types::{MarketId, OrderId, OrderType, Price, Qty, Side, TimeInForce};
use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap, VecDeque};

#[derive(Clone, Debug)]
pub struct OrderBook {
    market: MarketId,
    bids: BTreeMap<Reverse<Price>, VecDeque<OrderId>>,
    asks: BTreeMap<Price, VecDeque<OrderId>>,
    orders: HashMap<OrderId, Order>,
}

impl OrderBook {
    pub fn new(market: MarketId) -> Self {
        Self {
            market,
            bids: BTreeMap::new(),
            asks: BTreeMap::new(),
            orders: HashMap::new(),
        }
    }

    pub fn market(&self) -> MarketId {
        self.market
    }

    pub fn order_count(&self) -> u64 {
        self.orders
            .values()
            .filter(|o| o.remaining > 0)
            .count() as u64
    }

    pub fn get(&self, id: OrderId) -> Option<&Order> {
        self.orders.get(&id)
    }

    pub fn best_bid(&self) -> Option<(Price, Qty)> {
        for (Reverse(price), deque) in self.bids.iter() {
            let qty = self.level_qty(deque);
            if qty > 0 {
                return Some((*price, qty));
            }
        }
        None
    }

    pub fn best_ask(&self) -> Option<(Price, Qty)> {
        for (price, deque) in self.asks.iter() {
            let qty = self.level_qty(deque);
            if qty > 0 {
                return Some((*price, qty));
            }
        }
        None
    }

    fn level_qty(&self, deque: &VecDeque<OrderId>) -> Qty {
        deque
            .iter()
            .filter_map(|id| self.orders.get(id))
            .map(|o| o.remaining)
            .sum()
    }

    pub fn submit(&mut self, mut order: Order) -> Result<MatchResult, BookError> {
        if order.market != self.market {
            return Err(BookError::WrongMarket);
        }
        if order.qty == 0 || order.remaining == 0 {
            return Err(BookError::ZeroQty);
        }
        if order.typ == OrderType::Limit && order.price == 0 {
            return Err(BookError::ZeroPrice);
        }
        if self.orders.contains_key(&order.id) {
            return Err(BookError::DuplicateOrder);
        }

        let mut fills = Vec::new();
        let canceled_maker = Vec::new();
        let mut self_trade = false;

        while order.remaining > 0 {
            let head = match order.side {
                Side::Bid => self.next_ask_head(),
                Side::Ask => self.next_bid_head(),
            };
            let (maker_id, maker_price) = match head {
                Some(v) => v,
                None => break,
            };

            let crosses = match order.side {
                Side::Bid => match order.typ {
                    OrderType::Market => true,
                    OrderType::Limit => maker_price <= order.price,
                },
                Side::Ask => match order.typ {
                    OrderType::Market => true,
                    OrderType::Limit => maker_price >= order.price,
                },
            };
            if !crosses {
                break;
            }

            let maker_account = match self.orders.get(&maker_id) {
                Some(m) => m.account,
                None => {
                    self.pop_head(order.side.opposite());
                    continue;
                }
            };
            if maker_account == order.account {
                self_trade = true;
                break;
            }

            let maker = self.orders.get_mut(&maker_id).expect("maker present");
            let fill_qty = order.remaining.min(maker.remaining);
            maker.remaining -= fill_qty;
            order.remaining -= fill_qty;
            let maker_done = maker.remaining == 0;
            let maker_acct = maker.account;

            fills.push(Fill {
                taker_id: order.id,
                maker_id,
                taker: order.account,
                maker: maker_acct,
                market: order.market,
                price: maker_price,
                qty: fill_qty,
                seq: order.seq,
                taker_side: order.side,
            });

            if maker_done {
                self.orders.remove(&maker_id);
                self.pop_head(order.side.opposite());
            }
        }

        if self_trade {
            return Ok(MatchResult {
                fills,
                taker_remaining: 0,
                taker_resting: false,
                canceled_maker,
            });
        }

        let rest = order.typ == OrderType::Limit
            && order.tif == TimeInForce::Gtc
            && order.remaining > 0;

        let taker_remaining = if rest { order.remaining } else { 0 };
        if rest {
            self.enqueue(order);
        }

        Ok(MatchResult {
            fills,
            taker_remaining,
            taker_resting: rest,
            canceled_maker,
        })
    }

    pub fn cancel(&mut self, id: OrderId) -> Result<Order, BookError> {
        let order = self.orders.get(&id).ok_or(BookError::NotFound)?;
        if order.remaining == 0 {
            return Err(BookError::NotFound);
        }
        let price = order.price;
        let side = order.side;
        let mut order = self.orders.remove(&id).ok_or(BookError::NotFound)?;

        let deque = match side {
            Side::Bid => self.bids.get_mut(&Reverse(price)),
            Side::Ask => self.asks.get_mut(&price),
        };
        if let Some(dq) = deque {
            if dq.front() == Some(&id) {
                dq.pop_front();
                self.drop_empty_level(side, price);
            }
        }
        order.remaining = 0;
        Ok(order)
    }

    fn enqueue(&mut self, order: Order) {
        match order.side {
            Side::Bid => {
                self.bids
                    .entry(Reverse(order.price))
                    .or_default()
                    .push_back(order.id);
            }
            Side::Ask => {
                self.asks.entry(order.price).or_default().push_back(order.id);
            }
        }
        self.orders.insert(order.id, order);
    }

    fn next_ask_head(&mut self) -> Option<(OrderId, Price)> {
        loop {
            let price = *self.asks.keys().next()?;
            let dq = self.asks.get_mut(&price)?;
            while let Some(id) = dq.front().copied() {
                match self.orders.get(&id) {
                    Some(o) if o.remaining > 0 => return Some((id, price)),
                    _ => {
                        dq.pop_front();
                        self.orders.remove(&id);
                    }
                }
            }
            self.asks.remove(&price);
        }
    }

    fn next_bid_head(&mut self) -> Option<(OrderId, Price)> {
        loop {
            let Reverse(price) = *self.bids.keys().next()?;
            let dq = self.bids.get_mut(&Reverse(price))?;
            while let Some(id) = dq.front().copied() {
                match self.orders.get(&id) {
                    Some(o) if o.remaining > 0 => return Some((id, price)),
                    _ => {
                        dq.pop_front();
                        self.orders.remove(&id);
                    }
                }
            }
            self.bids.remove(&Reverse(price));
        }
    }

    fn pop_head(&mut self, maker_side: Side) {
        match maker_side {
            Side::Ask => {
                if let Some((&price, _)) = self.asks.iter().next() {
                    if let Some(dq) = self.asks.get_mut(&price) {
                        dq.pop_front();
                    }
                    self.drop_empty_level(Side::Ask, price);
                }
            }
            Side::Bid => {
                if let Some((&Reverse(price), _)) = self.bids.iter().next() {
                    if let Some(dq) = self.bids.get_mut(&Reverse(price)) {
                        dq.pop_front();
                    }
                    self.drop_empty_level(Side::Bid, price);
                }
            }
        }
    }

    fn drop_empty_level(&mut self, side: Side, price: Price) {
        match side {
            Side::Bid => {
                let empty = self
                    .bids
                    .get(&Reverse(price))
                    .map(|d| d.is_empty())
                    .unwrap_or(true);
                if empty {
                    self.bids.remove(&Reverse(price));
                }
            }
            Side::Ask => {
                let empty = self.asks.get(&price).map(|d| d.is_empty()).unwrap_or(true);
                if empty {
                    self.asks.remove(&price);
                }
            }
        }
    }
}
