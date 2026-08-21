use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Side {
    Bid,
    Ask,
}

impl Side {
    pub fn as_u8(self) -> u8 {
        match self {
            Side::Bid => 0,
            Side::Ask => 1,
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Side::Bid),
            1 => Some(Side::Ask),
            _ => None,
        }
    }

    pub fn opposite(self) -> Self {
        match self {
            Side::Bid => Side::Ask,
            Side::Ask => Side::Bid,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OrderType {
    Limit,
    Market,
}

impl OrderType {
    pub fn as_u8(self) -> u8 {
        match self {
            OrderType::Limit => 0,
            OrderType::Market => 1,
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(OrderType::Limit),
            1 => Some(OrderType::Market),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TimeInForce {
    Gtc,
    Ioc,
}

impl TimeInForce {
    pub fn as_u8(self) -> u8 {
        match self {
            TimeInForce::Gtc => 0,
            TimeInForce::Ioc => 1,
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(TimeInForce::Gtc),
            1 => Some(TimeInForce::Ioc),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExecStatus {
    Optimistic,
    Final,
}
