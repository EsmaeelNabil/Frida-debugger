import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.gestures.forEachGesture
import androidx.compose.foundation.layout.Box
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.window.WindowScope
import io.socket.client.Socket
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.callbackFlow
import network.SocketEvents
import utils.DragHandler
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter


fun <T> SocketEvents.onEventFlow(socket: Socket, evaluation: (Any?) -> T) = callbackFlow<T> {
    socket.on(this@onEventFlow.name) {
        trySend(evaluation(it.getOrNull(0)))
    }
    awaitClose { }
}


val currentTime get() = LocalDateTime.now().currentDateTimeString()

fun LocalDateTime.currentDateTimeString(pattern: String = "hh:mm:ss"): String {
    val formatter = DateTimeFormatter.ofPattern(pattern)
    return this.format(formatter)
}

val emptyString = "                              "

@Composable
fun WindowScope.WindowDraggableArea(
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit = {}
) {
    val handler = remember { DragHandler(window) }
    Box(
        modifier = modifier.pointerInput(Unit) {
            forEachGesture {
                awaitPointerEventScope {
                    awaitFirstDown()
                    handler.register()
                }
            }
        }
    ) {
        content()
    }
}

val defaultScript = "send(\"hi from frida\");"

@Composable
fun Modifier.setHorizontalGradient(
    colorStops: Array<Pair<Float, Color>> = arrayOf(
        0.0f to Color(0xFF348F50),
        1f to Color(0xFF56B4D3)
    )
) = this.then(
    background(
        brush = Brush.horizontalGradient(colorStops = colorStops)
    )
)