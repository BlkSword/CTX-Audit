// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! Agent 消息总线
//!
//! 处理 Agent 之间的通信

pub struct MessageBus;

impl MessageBus {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MessageBus {
    fn default() -> Self {
        Self::new()
    }
}
