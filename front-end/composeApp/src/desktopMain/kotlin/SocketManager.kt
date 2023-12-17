import io.socket.client.IO
import io.socket.client.Socket
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.callbackFlow
import java.net.URI


fun <T> onEventFlow(socket: Socket, event: String, evaluation: (Any?) -> T) = callbackFlow<T> {
    socket.on(event) {
        trySend(evaluation(it.getOrNull(0)))
    }
    awaitClose { }
}

object SocketManager {
    fun getClient(): Socket {
        val uri: URI = URI.create("ws://localhost:3002")
        val options = IO.Options.builder()
            .setReconnection(true)
            .setReconnectionAttempts(Integer.MAX_VALUE)
            .setReconnectionDelay(1_000)
            .setReconnectionDelayMax(5_000)
            .setRandomizationFactor(0.5)
            .setTimeout(20_000)
            .setAuth(null)
            .build()

        return IO.socket(uri, options).apply {
            onAnyIncoming {
                println("Incoming ${it.contentToString()}")
            }
            onAnyOutgoing {
                println("Outgoing ${it.contentToString()}")
            }
        }
    }
}