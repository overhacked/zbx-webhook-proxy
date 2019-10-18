use warp::{self, path, Filter, Reply};
use warp::filters::BoxedFilter;
use std::collections::HashMap;
use std::sync::Arc;
use std::net::SocketAddr;
use log::debug;
use serde_json::json;
use structopt::StructOpt;
use dns_lookup::lookup_addr;

#[derive(StructOpt, Debug)]
#[structopt(name = "serve")]
struct Cli {
    #[structopt(long = "listen", short = "l", default_value = "[::1]:3030")]
    listen: std::net::SocketAddr,

    #[structopt(long = "zabbix-server", short = "z")]
    zabbix_server: String,

    #[structopt(long = "zabbix-port", short = "p", default_value = "10051")]
    zabbix_port: u16,
}

fn main() {
    pretty_env_logger::init();
    
    let args = Cli::from_args();

    let zabbix: Arc<ZabbixLogger> = Arc::new(
        ZabbixLogger::new(&args.zabbix_server, args.zabbix_port)
    );
    
    let log = warp::log("iaevents::request");

    let iaevent = path("IAEvents")
        .and(warp::get2())
        .and(handle_iaevent(Arc::clone(&zabbix)))
        .with(log);

    warp::serve(iaevent)
        .run(args.listen);
}

fn handle_iaevent(zabbix: Arc<ZabbixLogger>) -> BoxedFilter<(impl Reply,)> {
    let string_params = warp::query::<HashMap<String,String>>();

    warp::addr::remote()
    .and(string_params)
    .map(move |remote: Option<SocketAddr>, params| {
        let j = json!(params);
        debug!("{}", j.to_string());
        let r = lookup_addr(&remote.unwrap().ip()).unwrap();
        zabbix.log(&r, &j.to_string()).expect("Zabbix failure");
    })
    .map(|_| warp::http::StatusCode::NO_CONTENT)
    .boxed()
}

struct ZabbixLogger {
    sender: zbx_sender::Sender,
}

impl ZabbixLogger {
    fn new(server: &str, port: u16) -> ZabbixLogger {
        ZabbixLogger { sender: zbx_sender::Sender::new(server.to_owned(), port) }
    }

    fn log(&self, host: &str, value: &str) -> zbx_sender::Result<zbx_sender::Response> {
        self.sender.send((host, "door.log", value))
    }
}
