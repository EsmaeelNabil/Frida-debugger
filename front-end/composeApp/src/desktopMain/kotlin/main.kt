import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Minimize
import androidx.compose.material.icons.filled.MoveToInbox
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.FrameWindowScope
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import androidx.compose.ui.window.rememberWindowState
import io.socket.client.Socket
import network.SocketManager
import theme.AppTheme


val LocalSocket = staticCompositionLocalOf<Socket> {
    error("No socket provided")
}

val LocalWindowFrameScope = staticCompositionLocalOf<FrameWindowScope> {
    error("No socket provided")
}

@OptIn(ExperimentalMaterial3Api::class)
fun main() = application {

    val socket = SocketManager.getClient().connect()

    CompositionLocalProvider(LocalSocket provides socket) {
        val windowState = rememberWindowState()
        Window(
            state = windowState,
            onCloseRequest = ::exitApplication,
            transparent = true,
            undecorated = true,
            title = "Compose App"
        ) {
            AppTheme {
                WindowDraggableArea {
                    CompositionLocalProvider(LocalWindowFrameScope provides this) {
                        App(
                            onMainApplicationClose = ::exitApplication,
                            onMainApplicationMinimize = {
                                windowState.isMinimized = true
                            }
                        )
                    }
                }
            }
        }
    }

}


@Composable
fun ControlIcon(
    modifier: Modifier = Modifier,
    containerSize: Dp = 24.dp,
    iconSize: Dp = 10.dp,
    icon: ImageVector,
    onClick: () -> Unit = { }
) {

    Surface(modifier, shape = CircleShape) {
        IconButton(
            modifier = Modifier.size(containerSize),
            onClick = onClick
        ) {
            Icon(
                modifier = Modifier.size(iconSize),
                imageVector = icon,
                contentDescription = "Close",
            )
        }
    }
}