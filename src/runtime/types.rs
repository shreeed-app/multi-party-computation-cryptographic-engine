//! Runtime types module.

use std::io::Error as IoError;

use futures::{future::BoxFuture, stream::Unfold};
use tokio::net::{TcpListener, TcpStream};

/// Type alias for an incoming TCP stream using `Unfold` to handle incoming
/// connections.
pub type IncomingStream = Unfold<
    TcpListener,
    fn(
        TcpListener,
    ) -> BoxFuture<
        'static,
        Option<(Result<TcpStream, IoError>, TcpListener)>,
    >,
    BoxFuture<'static, Option<(Result<TcpStream, IoError>, TcpListener)>>,
>;
