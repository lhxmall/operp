mod book;

pub use book::OrderBook;

use operp_types::{AccountId, MarketId, OrderId, OrderType, Price, Qty, Seq, Side, TimeInForce};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Order {
    pub id: OrderId,
    pub account: AccountId,
    pub market: MarketId,
    pub side: Side,
    pub typ: OrderType,
    pub tif: TimeInForce,
    pub price: Price,
    pub qty: Qty,
    pub remaining: Qty,
    pub seq: Seq,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fill {
    pub taker_id: OrderId,
    pub maker_id: OrderId,
    pub taker: AccountId,
    pub maker: AccountId,
    pub market: MarketId,
    pub price: Price,
    pub qty: Qty,
    pub seq: Seq,
    pub taker_side: Side,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MatchResult {
    pub fills: Vec<Fill>,
    pub taker_remaining: Qty,
    pub taker_resting: bool,
    pub canceled_maker: Vec<OrderId>,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum BookError {
    #[error("not found")]
    NotFound,
    #[error("zero qty")]
    ZeroQty,
    #[error("zero price")]
    ZeroPrice,
    #[error("duplicate order")]
    DuplicateOrder,
    #[error("wrong market")]
    WrongMarket,
}

#[cfg(test)]
mod tests {
    use super::*;
    use operp_types::{order_id, BTC_USD, PRICE_SCALE, QTY_SCALE};

    fn acct(n: u8) -> AccountId {
        AccountId([n; 32])
    }

    fn oid(a: AccountId, seq: u64) -> OrderId {
        order_id(a, BTC_USD, seq)
    }

    fn order(
        account: AccountId,
        client_seq: u64,
        side: Side,
        typ: OrderType,
        tif: TimeInForce,
        price: Price,
        qty: Qty,
        seq: Seq,
    ) -> Order {
        let id = oid(account, client_seq);
        Order {
            id,
            account,
            market: BTC_USD,
            side,
            typ,
            tif,
            price,
            qty,
            remaining: qty,
            seq,
        }
    }

    #[test]
    fn limit_buy_crosses_one_sell() {
        let mut book = OrderBook::new(BTC_USD);
        let maker = acct(1);
        let taker = acct(2);
        let px = 100 * PRICE_SCALE;
        let qty = QTY_SCALE;
        book.submit(order(
            maker,
            1,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            qty,
            1,
        ))
        .unwrap();
        let r = book
            .submit(order(
                taker,
                1,
                Side::Bid,
                OrderType::Limit,
                TimeInForce::Gtc,
                px + PRICE_SCALE,
                qty * 2,
                2,
            ))
            .unwrap();
        assert_eq!(r.fills.len(), 1);
        assert_eq!(r.fills[0].price, px);
        assert_eq!(r.fills[0].qty, qty);
        assert!(r.taker_resting);
        assert_eq!(r.taker_remaining, qty);
        assert_eq!(book.best_bid().unwrap().0, px + PRICE_SCALE);
    }

    #[test]
    fn partial_fill_then_rest() {
        let mut book = OrderBook::new(BTC_USD);
        let maker = acct(1);
        let taker = acct(2);
        let px = 50 * PRICE_SCALE;
        book.submit(order(
            maker,
            1,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            QTY_SCALE / 2,
            1,
        ))
        .unwrap();
        let r = book
            .submit(order(
                taker,
                1,
                Side::Bid,
                OrderType::Limit,
                TimeInForce::Gtc,
                px,
                QTY_SCALE,
                2,
            ))
            .unwrap();
        assert_eq!(r.fills[0].qty, QTY_SCALE / 2);
        assert!(r.taker_resting);
        assert_eq!(r.taker_remaining, QTY_SCALE / 2);
    }

    #[test]
    fn market_buy_eats_two_ask_levels() {
        let mut book = OrderBook::new(BTC_USD);
        let maker = acct(1);
        let taker = acct(2);
        book.submit(order(
            maker,
            1,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            100 * PRICE_SCALE,
            QTY_SCALE,
            1,
        ))
        .unwrap();
        book.submit(order(
            maker,
            2,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            101 * PRICE_SCALE,
            QTY_SCALE,
            2,
        ))
        .unwrap();
        let r = book
            .submit(order(
                taker,
                1,
                Side::Bid,
                OrderType::Market,
                TimeInForce::Ioc,
                0,
                2 * QTY_SCALE,
                3,
            ))
            .unwrap();
        assert_eq!(r.fills.len(), 2);
        assert_eq!(r.fills[0].price, 100 * PRICE_SCALE);
        assert_eq!(r.fills[1].price, 101 * PRICE_SCALE);
        assert!(!r.taker_resting);
        assert_eq!(book.best_ask(), None);
    }

    #[test]
    fn cancel_resting_then_missing_errors() {
        let mut book = OrderBook::new(BTC_USD);
        let a = acct(1);
        let o = order(
            a,
            1,
            Side::Bid,
            OrderType::Limit,
            TimeInForce::Gtc,
            10 * PRICE_SCALE,
            QTY_SCALE,
            1,
        );
        let id = o.id;
        book.submit(o).unwrap();
        book.cancel(id).unwrap();
        assert!(matches!(book.cancel(id), Err(BookError::NotFound)));
    }

    #[test]
    fn self_trade_cancel_taker() {
        let mut book = OrderBook::new(BTC_USD);
        let a = acct(1);
        book.submit(order(
            a,
            1,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            100 * PRICE_SCALE,
            QTY_SCALE,
            1,
        ))
        .unwrap();
        let r = book
            .submit(order(
                a,
                2,
                Side::Bid,
                OrderType::Limit,
                TimeInForce::Gtc,
                100 * PRICE_SCALE,
                QTY_SCALE,
                2,
            ))
            .unwrap();
        assert!(r.fills.is_empty());
        assert!(!r.taker_resting);
        assert!(r.canceled_maker.is_empty());
        assert!(book.get(oid(a, 1)).is_some());
        assert!(book.get(oid(a, 2)).is_none());
    }

    #[test]
    fn price_time_fifo_same_price() {
        let mut book = OrderBook::new(BTC_USD);
        let m1 = acct(1);
        let m2 = acct(2);
        let t = acct(3);
        let px = 100 * PRICE_SCALE;
        book.submit(order(
            m1,
            1,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            QTY_SCALE,
            1,
        ))
        .unwrap();
        book.submit(order(
            m2,
            1,
            Side::Ask,
            OrderType::Limit,
            TimeInForce::Gtc,
            px,
            QTY_SCALE,
            2,
        ))
        .unwrap();
        let r = book
            .submit(order(
                t,
                1,
                Side::Bid,
                OrderType::Limit,
                TimeInForce::Gtc,
                px,
                QTY_SCALE,
                3,
            ))
            .unwrap();
        assert_eq!(r.fills.len(), 1);
        assert_eq!(r.fills[0].maker, m1);
        assert_eq!(book.get(oid(m2, 1)).unwrap().remaining, QTY_SCALE);
        assert_eq!(book.best_ask().unwrap(), (px, QTY_SCALE));
    }
}
