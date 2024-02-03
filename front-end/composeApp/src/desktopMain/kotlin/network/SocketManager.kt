package network

import io.socket.client.IO
import io.socket.client.Socket
import java.net.URI


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