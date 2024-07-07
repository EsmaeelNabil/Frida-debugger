package network

import io.socket.client.IO
import io.socket.client.Socket
import java.net.URI

/**
 * This object manages the socket connection for the application.
 * It provides a function to get a socket client with specific options.
 */
object SocketManager {

    /**
     * This function returns a socket client with specific options.
     * The options include reconnection, reconnection attempts, reconnection delay, reconnection delay max, randomization factor, timeout, and auth.
     * The socket client is set to print incoming and outgoing events.
     * @return The socket client.
     *
     * Example usage:
     * ```kotlin
     * val socketClient = SocketManager.getClient()
     * ```
     */
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