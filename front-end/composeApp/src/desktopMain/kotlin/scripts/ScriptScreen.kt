package scripts

import ScriptInputDialog
import network.SocketEvents
import androidx.compose.desktop.ui.tooling.preview.Preview
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import currentTime
import defaultScript
import io.socket.client.Socket
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import models.Application
import models.Device
import onEventFlow

/**
 * This function displays the script screen.
 *
 * @param socket The socket connection to the server.
 * @param selectedDevice The device that has been selected by the user.
 * @param selectedApp The application that has been selected by the user.
 * @param onBack The action to be performed when the back button is clicked.
 *
 * Example usage:
 * ```kotlin
 * ScriptScreen(
 *     socket = socket,
 *     selectedDevice = device,
 *     selectedApp = app,
 *     onBack = { /* action to perform on back button click */ }
 * )
 */
@Composable
fun ScriptScreen(socket: Socket, selectedDevice: Device, selectedApp: Application, onBack: () -> Job) {

    val messages = remember { mutableStateListOf("\n") }
    val scrollState = rememberLazyListState()
    val scope = rememberCoroutineScope()
    var autoScrollEnabled by remember { mutableStateOf(false) }
    var showScriptInputDialog by remember { mutableStateOf(false) }
    var initialScript by remember { mutableStateOf(defaultScript) }

    LaunchedEffect(Unit) {
        SocketEvents.ON_MESSAGE.onEventFlow(
            socket = socket, evaluation = { it.toString() }
        ).collect {
            messages.add("$currentTime : $it")
            scope.launch {
                if (autoScrollEnabled)
                    if (scrollState.isScrollInProgress.not())
                        scrollState.animateScrollToItem(messages.lastIndex)
            }
        }
    }

    Surface(
        shape = RoundedCornerShape(24.dp),
        shadowElevation = 2.dp,
        modifier = Modifier.padding(16.dp),
        color = Color.White
    ) {
        Box {
            Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {

                Row {
                    IconButton(onClick = {
                        onBack()
                    }) {
                        Icon(Icons.Filled.ArrowBack, null)
                    }

                    ButtonDebugger(
                        onClick = { autoScrollEnabled = !autoScrollEnabled }
                    ) {
                        Text("${if (autoScrollEnabled) "Disable" else "Enable"} Auto scroll")
                        Spacer(Modifier.width(16.dp))
                        Icon(if (autoScrollEnabled) Icons.Filled.SwipeDown else Icons.Filled.SwipeUp, null)
                    }

                    Spacer(modifier = Modifier.width(16.dp))



                    Spacer(modifier = Modifier.width(16.dp))

                    ButtonDebugger(
                        onClick = { socket.emit(SocketEvents.UNLOAD_SCRIPTS.name) }
                    ) {
                        Text("Unload Scripts")
                    }

                    ButtonDebugger(
                        onClick = { messages.clear() }
                    ) {
                        Text("Clear")
                    }

                    Spacer(modifier = Modifier.width(16.dp))

                    ButtonDebugger(onClick = {
                        showScriptInputDialog = true
                    }) {
                        Text("Custom Script")
                        Spacer(modifier = Modifier.width(16.dp))
                        Icon(Icons.Filled.Book, null)
                    }

                }


                ScriptMessageComponent(messages, scrollState)


            }
            Column(modifier = Modifier.align(Alignment.BottomEnd)) {
                IconButton(
                    onClick = {
                        scope.launch {
                            scrollState.animateScrollToItem(0)
                        }
                    }) {
                    Icon(Icons.Filled.ArrowDropUp, null)
                }

                IconButton(
                    onClick = {
                        scope.launch {
                            scrollState.animateScrollToItem(messages.lastIndex)
                        }
                    }) {
                    Icon(Icons.Filled.ArrowDropDown, null)
                }
            }

            if (showScriptInputDialog) {
                ScriptInputDialog(
                    initialScript = initialScript,
                    onDismissRequest = { showScriptInputDialog = !showScriptInputDialog },
                    onConfirmation = { newScript ->
                        initialScript = newScript
                        socket.emit(
                            SocketEvents.ATTACH.name,
                            listOf(
                                selectedDevice.deviceDetails.id,
                                selectedApp.name,
                                newScript
                            )
                        )
                    }
                )
            }
        }
    }

}

/**
 * This function displays the script message component.
 *
 * @param messages The list of messages to be displayed.
 * @param scrollState The state of the scroll.
 *
 * Example usage:
 * ```kotlin
 * ScriptMessageComponent(
 *     messages = listOf("message1", "message2"),
 *     scrollState = rememberLazyListState()
 * )
 */
@Preview()
@Composable
fun ScriptMessageComponent(messages: List<String>, scrollState: LazyListState) {
    LazyColumn(state = scrollState) {
        items(messages) { message ->
            SelectionContainer {
                Text(text = message, fontWeight = FontWeight.Light, color = Color.Black, fontSize = 14.sp)
            }
        }
    }
}

/**
 * This function displays the button debugger.
 *
 * @param onClick The action to be performed when the button is clicked.
 * @param content The content to be displayed on the button.
 *
 * Example usage:
 * ```kotlin
 * ButtonDebugger(
 *     onClick = { /* action to perform on button click */ },
 *     content = {
 *         Text("Button")
 *     }
 * )
 */
@Composable
fun ButtonDebugger(
    onClick: () -> Unit, content: @Composable RowScope.() -> Unit
) {
    Button(
        colors = ButtonDefaults.buttonColors(
            contentColor = Color.Gray,
            containerColor = Color.White
        ),
        elevation = ButtonDefaults.buttonElevation(defaultElevation = 3.dp),
        onClick = onClick,
        content = content
    )
}
