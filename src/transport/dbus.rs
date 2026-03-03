use crate::transport::S2Transport;
use futures_util::StreamExt;
use std::time::Duration;
use uuid::Uuid;
use zbus::{Connection, connection, fdo::DBusProxy, names::OwnedBusName, proxy};

#[derive(Debug, thiserror::Error)]
pub enum S2DBusError {
    #[error("Discover() returned false")]
    DiscoverReturnedFalse,
    #[error("there's already a CEM connected to that RM")]
    AlreadyConnectedCem,
    #[error("reached end of stream for a dbus signal; this should never happen")]
    EndOfStream,
    #[error("could not (de)serialize message: {0}")]
    SerializationError(#[from] serde_json::Error),
    #[error("dbus error: {0}")]
    DBusError(#[from] zbus::Error),
}

#[derive(Debug)]
pub struct DBusServer {
    connection: Connection,
    pending_names: Vec<OwnedBusName>,
    cem_id: String,
    dbus_name: String,
}

impl DBusServer {
    pub async fn new(dbus_name: impl Into<String>) -> Result<Self, S2DBusError> {
        let dbus_name = dbus_name.into();
        tracing::trace!("Connecting to D-Bus with name {dbus_name}");
        let connection = connection::Builder::system()?
            .name(dbus_name.as_str())?
            .method_timeout(Duration::from_secs(5))
            .build()
            .await?;
        let dbus = DBusProxy::new(&connection).await?;
        let pending_names = dbus.list_names().await.map_err(zbus::Error::from)?;
        tracing::trace!("Connected to D-Bus, identified some existing names: {pending_names:#?}");
        Ok(Self {
            connection,
            pending_names,
            cem_id: Uuid::new_v4().to_string(),
            dbus_name,
        })
    }

    pub async fn receive_connection(&mut self) -> Result<DBusConnection, S2DBusError> {
        // First go through our list of saved names that we haven't processed yet
        while let Some(name) = self.pending_names.pop() {
            if self.connection.unique_name().map(|own_name| ***own_name == **name).unwrap_or(false) || name == self.dbus_name.as_str() {
                // Skip our own name, connecting to ourselves does not go well
                continue;
            }

            match DBusConnection::new(&self.cem_id, &self.connection, name).await {
                Ok(connection) => return Ok(connection),
                Err(err) => {
                    tracing::trace!("D-Bus connection skipped; reason: {err:?}");
                }
            }
        }

        // Wait on NameOwnerChanged signal to look for new objects to connect to.
        let dbus = DBusProxy::new(&self.connection).await.map_err(zbus::Error::from)?;
        while let Some(new_object) = dbus.receive_name_owner_changed().await?.next().await {
            let args = new_object.args().unwrap();
            match DBusConnection::new(&self.cem_id, &self.connection, args.name.into()).await {
                Ok(connection) => return Ok(connection),
                Err(err) => {
                    tracing::trace!("D-Bus connection skipped; reason: {err:?}");
                }
            }
        }

        Err(S2DBusError::EndOfStream)
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

pub struct DBusConnection(String, S2RmProxy<'static>);

impl DBusConnection {
    async fn new(cem_id: impl Into<String>, connection: &Connection, destination: OwnedBusName) -> Result<Self, S2DBusError> {
        let cem_id = cem_id.into();

        tracing::trace!("Attempting D-Bus connection to {destination:?}");
        let rm_proxy = S2RmProxy::builder(connection).destination(destination)?.build().await?;
        if !rm_proxy.discover().await? {
            return Err(S2DBusError::DiscoverReturnedFalse);
        }

        let connected = rm_proxy.connect(cem_id.clone(), 30).await?;
        if !connected {
            return Err(S2DBusError::AlreadyConnectedCem);
        }

        Ok(Self(cem_id, rm_proxy))
    }
}

impl S2Transport for DBusConnection {
    type TransportError = S2DBusError;

    async fn send(&mut self, message: crate::common::Message) -> Result<(), Self::TransportError> {
        tracing::trace!("Sending S2 message over D-Bus: {message:?}");
        let serialized = serde_json::to_string(&message)?;
        self.1.message(self.0.clone(), serialized).await?;
        Ok(())
    }

    async fn receive(&mut self) -> Result<crate::common::Message, Self::TransportError> {
        let serialized_contents = self
            .1
            .receive_message()
            .await?
            .next()
            .await
            .ok_or(S2DBusError::EndOfStream)?
            .args()?
            .message;
        tracing::trace!("Received message over D-Bus: {serialized_contents:?}");
        let msg: crate::common::Message = serde_json::from_str(&serialized_contents)?;
        Ok(msg)
    }

    async fn disconnect(self) {
        let _ = self.1.disconnect(self.0).await;
    }
}

// #[tokio::main]
// async fn main() -> eyre::Result<()> {
//     if std::env::var("SERVER").map(|var| var == "true").unwrap_or(false) {
//         let mut server = DBusServer::new().await?;
//         loop {
//             let mut connection = server.receive_connection().await?;
//             println!("Acquired connection :D");
//             connection.send(frbc::StorageStatus::new(10.).into()).await?;
//         }
//     } else {
//         let connection = Connection::system().await?;
//         println!("Sleeping for 2 seconds.");
//         tokio::time::sleep(Duration::from_secs(2)).await;
//         println!("Acquiring name.");
//         connection.request_name("nl.westercoenraads.S2").await?;
//         tokio::time::sleep(Duration::from_secs(2)).await;
//         println!("Releasing name.");
//         connection.release_name("nl.westercoenraads.S2").await?;
//         // S2RmProxy::new(conn, destination)
//     }

//     Ok(())
// }
