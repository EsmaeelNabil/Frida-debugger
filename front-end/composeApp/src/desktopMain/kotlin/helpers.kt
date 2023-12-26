import io.socket.client.Socket
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.callbackFlow
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter

fun <T> onEventFlow(socket: Socket, event: String, evaluation: (Any?) -> T) = callbackFlow<T> {
    socket.on(event) {
        trySend(evaluation(it.getOrNull(0)))
    }
    awaitClose { }
}

fun LocalDateTime.currentDateTimeString(pattern: String = "hh:mm:ss"): String {
    val formatter = DateTimeFormatter.ofPattern(pattern)
    return this.format(formatter)
}