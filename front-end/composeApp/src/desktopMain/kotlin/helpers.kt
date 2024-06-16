import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.gestures.forEachGesture
import androidx.compose.foundation.layout.Box
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
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

/**
 * Extension function to listen for a specific socket event and emit its data as a flow.
 *
 * @param T The type of data to emit.
 * @param socket The Socket instance to listen to.
 * @param evaluation A function to process the received event data.
 * @return A flow that emits the processed event data.
 *
 * Example usage:
 * ```kotlin
 * val messageFlow = socket.onEventFlow(SocketEvents.ON_MESSAGE) { it.toString() }
 * ```
 */
fun <T> SocketEvents.onEventFlow(socket: Socket, evaluation: (Any?) -> T) = callbackFlow<T> {
    socket.on(this@onEventFlow.name) {
        trySend(evaluation(it.getOrNull(0)))
    }
    awaitClose { }
}

/**
 * Property to get the current time formatted as a string.
 *
 * Example usage:
 * ```kotlin
 * val currentTime = LocalDateTime.now().currentDateTimeString()
 * ```
 */
val currentTime get() = LocalDateTime.now().currentDateTimeString()

/**
 * Extension function to format a LocalDateTime object as a string.
 *
 * @param pattern The pattern to format the date-time string.
 * @return The formatted date-time string.
 *
 * Example usage:
 * ```kotlin
 * val dateTimeString = LocalDateTime.now().currentDateTimeString("yyyy-MM-dd hh:mm:ss")
 * ```
 *
 */
fun LocalDateTime.currentDateTimeString(pattern: String = "hh:mm:ss"): String {
    val formatter = DateTimeFormatter.ofPattern(pattern)
    return this.format(formatter)
}

/**
 * A constant empty string.
 */
val emptyString = "                              "

/**
 * A composable function to create a draggable area in a window.
 *
 * @param modifier The modifier to apply to this layout.
 * @param content The content to display inside the draggable area.
 *
 * Example usage:
 * ```kotlin
 * WindowDraggableArea {
 *    // content to display
 *    // ...
 *    // ...
 *    // ...
 *    // ...
 *    // ...
 *    // ...
 * }
 * ```
 */
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

/**
 * A constant script for sending a default message.
 */
val defaultScript = "send(\"hi from frida\");"

/**
 * Extension function to apply a horizontal gradient background to a modifier.
 *
 * @param colorStops The array of color stops for the gradient.
 * @return The modified Modifier with the gradient background applied.
 *
 * Example usage:
 * ```kotlin
 * Modifier.setHorizontalGradient()
 * ```
 */
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