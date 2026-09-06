use crate::{BookError, Fill, MatchResult, Order};
use operp_types::{MarketId, OrderId, OrderType, Price, Qty, Side, TimeInForce};
use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap, VecDeque};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct OrderBook {
    market: MarketId,
    bids: BTreeMap<Reverse<Price>, VecDeque<OrderId>>,
    asks: BTreeMap<Price, VecDeque<OrderId>>,
    orders: HashMap<OrderId, Order>,
    /// Incrementally-maintained visible qty per price level (bids).
    bid_qty: BTreeMap<Reverse<Price>, Qty>,
    /// Incrementally-maintained visible qty per price level (asks).
    ask_qty: BTreeMap<Price, Qty>,
}

impl OrderBook {
    pub fn new(market: MarketId) -> Self {
        Self {
            market,
            bids: BTreeMap::new(),
            asks: BTreeMap::new(),
            orders: HashMap::new(),
            bid_qty: BTreeMap::new(),
            ask_qty: BTreeMap::new(),
        }
    }

    pub fn market(&self) -> MarketId {
        self.market
    }

    pub fn order_count(&self) -> u64 {
        self.orders.values().filter(|o| o.remaining > 0).count() as u64
    }

    /// Canonical commitment over the FULL resting book — every price level and
    /// every live order, not just best bid/ask/count. Encoding:
    ///   b"book" || market le4
    ///   || for each ask level ascending by price, then each bid level
    ///      descending by price:
    ///        price le8 || live-order count u32le
    ///        || per live order in deque order (stale ids not present in
    ///           `orders`, if any, are skipped):
    ///            order_id 32B || remaining le8
    /// BTreeMap iteration makes level order deterministic across replays.
    /// O(book size) — fine for settlement-time commitment.
    pub fn commitment_bytes(&self) -> Vec<u8> {
        fn encode_level(
            b: &mut Vec<u8>,
            price: Price,
            q: &VecDeque<OrderId>,
            orders: &HashMap<OrderId, Order>,
        ) {
            let mut body = Vec::new();
            let mut live = 0u32;
            for id in q {
                if let Some(o) = orders.get(id) {
                    live += 1;
                    body.extend_from_slice(&o.id.0);
                    body.extend_from_slice(&o.remaining.to_le_bytes());
                }
            }
            b.extend_from_slice(&price.to_le_bytes());
            b.extend_from_slice(&live.to_le_bytes());
            b.extend_from_slice(&body);
        }
        let mut b = Vec::new();
        b.extend_from_slice(b"book");
        b.extend_from_slice(&self.market.0.to_le_bytes());
        // asks BTreeMap iterates ascending; bids keyed Reverse<Price> iterate
        // descending — both canonical.
        for (price, q) in &self.asks {
            encode_level(&mut b, *price, q, &self.orders);
        }
        for (price, q) in &self.bids {
            encode_level(&mut b, price.0, q, &self.orders);
        }
        b
    }

    pub fn get(&self, id: OrderId) -> Option<&Order> {
        self.orders.get(&id)
    }
    /// Live orders (remaining > 0) for witness-leaf commitment.
    pub fn live_orders(&self) -> impl Iterator<Item = &Order> {
        self.orders.values().filter(|o| o.remaining > 0)
    }

    pub fn best_bid(&self) -> Option<(Price, Qty)> {
        // O(log depth): cached visible qty; zero-qty levels pruned on update.
        self.bid_qty
            .iter()
            .next()
            .map(|(Reverse(price), q)| (*price, *q))
    }

    pub fn best_ask(&self) -> Option<(Price, Qty)> {
        self.ask_qty.iter().next().map(|(price, q)| (*price, *q))
    }

    fn level_add(&mut self, side: Side, price: Price, delta: i64) {
        match side {
            Side::Bid => {
                let e = self.bid_qty.entry(Reverse(price)).or_insert(0);
                *e = (*e as i64 + delta) as Qty;
                if *e == 0 {
                    self.bid_qty.remove(&Reverse(price));
                }
            }
            Side::Ask => {
                let e = self.ask_qty.entry(price).or_insert(0);
                *e = (*e as i64 + delta) as Qty;
                if *e == 0 {
                    self.ask_qty.remove(&price);
                }
            }
        }
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
        let mut canceled_maker = Vec::new();

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

            let (maker_account, maker_side, maker_remaining) = match self.orders.get(&maker_id) {
                Some(m) => (m.account, m.side, m.remaining),
                None => {
                    self.pop_head(order.side.opposite());
                    continue;
                }
            };
            if maker_account == order.account {
                // STP (cancel-maker-continue): the taker hit its own resting
                // order; cancel that maker and keep matching the queue.
                // Cache: canceled maker's visible qty leaves the level.
                self.level_add(maker_side, maker_price, -(maker_remaining as i64));
                canceled_maker.push(maker_id);
                self.orders.remove(&maker_id);
                self.pop_head(maker_side);
                continue;
            }

            let (fill_qty, maker_side, maker_acct, maker_done) = {
                let maker = self.orders.get_mut(&maker_id).expect("maker present");
                let fill_qty = order.remaining.min(maker.remaining);
                maker.remaining -= fill_qty;
                order.remaining -= fill_qty;
                let maker_done = maker.remaining == 0;
                (fill_qty, maker.side, maker.account, maker_done)
            };
            // Cache: maker's visible qty shrinks by the filled amount.
            self.level_add(maker_side, maker_price, -(fill_qty as i64));

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
                self.pop_head(maker_side);
            }
        }

        let rest =
            order.typ == OrderType::Limit && order.tif == TimeInForce::Gtc && order.remaining > 0;

        let taker_remaining = if rest { order.remaining } else { 0 };
        if rest {
            let (order_side, order_price, q) = (order.side, order.price, order.remaining);
            self.enqueue(order);
            // Cache: resting order adds visible qty at its level.
            self.level_add(order_side, order_price, q as i64);
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

        let removed = {
            let dq = match side {
                Side::Bid => self.bids.get_mut(&Reverse(price)),
                Side::Ask => self.asks.get_mut(&price),
            };
            match dq {
                Some(dq) => match dq.iter().position(|x| x == &id) {
                    Some(pos) => {
                        dq.remove(pos);
                        true
                    }
                    None => false,
                },
                None => false,
            }
        };
        // Visible qty is defined by order existence, not queue position: the
        // cache decrements for EVERY cancel, and the id is removed from its
        // level deque so no ghost ids linger.
        self.level_add(side, price, -(order.remaining as i64));
        if removed {
            self.drop_empty_level(side, price);
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
                self.asks
                    .entry(order.price)
                    .or_default()
                    .push_back(order.id);
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
