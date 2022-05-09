use std::borrow::Borrow;

use log::{info, debug};

pub struct ZabbixLogger {
    sender: zbx_sender::Sender,
}

impl ZabbixLogger {
    pub fn new(server: impl Into<String>, port: u16) -> Self {
        let server = server.into();

        info!(
            "Logging to Zabbix Server at {}:{}",
            server, port
        );
        Self {
            sender: zbx_sender::Sender::new(server, port),
        }
    }

    pub fn log_many(&self,
        host: &str,
        values: impl IntoIterator<Item = impl Borrow<ZabbixItemValue>>
    )
        -> zbx_sender::Result<zbx_sender::Response>
    {
        let values: Vec<zbx_sender::SendValue> = values.into_iter()
            .map(|i| {
                let i = i.borrow();
                (host, i.key.as_str(), i.value.as_str(),).into()
            })
            .collect();

        debug!("sending to Zabbix `{:?}`", values);
        self.sender.send(values)
    }

    // fn log(&self, host: &str, key: &str, value: &str) -> zbx_sender::Result<zbx_sender::Response> {
    //     self.log_many(host, [(key, value,)])
    // }
}

#[derive(Debug)]
pub struct ZabbixItemValue {
    pub key: String,
    pub value: String,
}

impl<S> From<(S, S,)> for ZabbixItemValue
    where S: Into<String>
{
    fn from((key, value,): (S, S,)) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}

