#![cfg(feature = "dbus")]
use futures_util::StreamExt;
use s2energy::transport::S2Transport;
use std::time::Duration;
use zbus::{Connection, fdo::DBusProxy, names::OwnedBusName, proxy};

struct DBusServer {
    connection: Connection,
    pending_names: Vec<OwnedBusName>,
}

impl DBusServer {
    async fn new() -> eyre::Result<Self> {
        let connection = Connection::system().await?;
        let dbus = DBusProxy::new(&connection).await?;
        let pending_names = dbus.list_names().await?;
        Ok(Self { connection, pending_names })
    }

    async fn receive_connection(&mut self) -> eyre::Result<DBusConnection> {
        while let Some(name) = self.pending_names.pop() {
            let proxy = match S2RmProxy::builder(&self.connection).destination(name)?.build().await {
                Ok(result) => result,
                Err(_) => continue,
            };
            let connection_handle = DBusConnection(String::new(), proxy);
            return Ok(connection_handle);
        }

        let dbus = DBusProxy::new(&self.connection).await?;
        let changed = dbus.receive_name_owner_changed().await?.next().await.ok_or(eyre::eyre!("oh no"))?;
        dbg!(changed.args().unwrap());
        // Ok(changed.to_string())
        Ok(todo!())
    }
}

#[proxy(default_path = "/S2/0/Rm", interface = "com.victronenergy.S2")]
trait S2Rm {
    fn discover(&self) -> zbus::Result<bool>;
    fn connect(&self, cem_id: String, keep_alive_internal: i32) -> zbus::Result<bool>;
    fn disconnect(&self, cem_id: String) -> zbus::Result<()>;
    fn message(&self, cem_id: String, message: String) -> zbus::Result<()>;
    fn keep_alive(&self, cem_id: String) -> zbus::Result<bool>;

    #[zbus(signal)]
    fn message(cem_id: String, message: String);
    #[zbus(signal)]
    fn disconnect(cem_id: String, reason: String);
}

struct DBusConnection(String, S2RmProxy<'static>);

impl S2Transport for DBusConnection {
    type TransportError = std::io::Error;

    async fn send(&mut self, message: s2energy::common::Message) -> Result<(), Self::TransportError> {
        todo!()
    }

    async fn receive(&mut self) -> Result<s2energy::common::Message, Self::TransportError> {
        todo!()
    }

    async fn disconnect(self) {
        self.1.disconnect(self.0).await;
    }
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    if std::env::var("SERVER").map(|var| var == "true").unwrap_or(false) {
        let mut server = DBusServer::new().await?;
        loop {
            server.receive_connection().await?;
        }
    } else {
        let connection = Connection::system().await?;
        println!("Sleeping for 2 seconds.");
        tokio::time::sleep(Duration::from_secs(2)).await;
        println!("Acquiring name.");
        connection.request_name("nl.westercoenraads.S2").await?;
        tokio::time::sleep(Duration::from_secs(2)).await;
        println!("Releasing name.");
        connection.release_name("nl.westercoenraads.S2").await?;
        // S2RmProxy::new(conn, destination)
    }

    Ok(())
}
