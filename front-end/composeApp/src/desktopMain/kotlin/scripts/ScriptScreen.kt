package scripts

import ScriptInputDialog
import SocketEvents
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
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
import androidx.compose.ui.unit.dp
import currentDateTimeString
import defaultScript
import io.socket.client.Socket
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import models.Application
import models.Device
import onEventFlow
import java.time.LocalDateTime

@Composable
fun ScriptScreen(socket: Socket, selectedDevice: Device, selectedApp: Application, onBack: () -> Job) {

    val messages = remember { mutableStateListOf("\n") }
    val scrollState = rememberLazyListState()
    val scope = rememberCoroutineScope()
    var autoScrollEnabled by remember { mutableStateOf(false) }
    var showScriptInputDialog by remember { mutableStateOf(false) }
    var initialScript by remember { mutableStateOf(defaultScript) }

    LaunchedEffect(Unit) {
        onEventFlow(
            socket = socket,
            event = SocketEvents.ON_MESSAGE.name,
            evaluation = {
                it.toString()
            }
        ).collect {
            messages.add("${LocalDateTime.now().currentDateTimeString()} : $it")
            scope.launch {
                if (autoScrollEnabled)
                    if (scrollState.isScrollInProgress.not())
                        scrollState.animateScrollToItem(messages.lastIndex)
            }
        }
    }

    Surface(shape = RoundedCornerShape(24.dp), shadowElevation = 2.dp, modifier = Modifier.padding(16.dp)) {
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

                    ButtonDebugger(
                        onClick = {
                            socket.emit(
                                SocketEvents.ATTACH.name,
                                listOf(
                                    selectedDevice.deviceDetails.id,
                                    selectedApp.name,
                                    defaultScript
                                )
                            )
                        }
                    ) {
                        Text("Load Defaults")
                    }

                    Spacer(modifier = Modifier.width(16.dp))

                    ButtonDebugger(
                        onClick = { socket.emit(SocketEvents.UNLOAD_SCRIPTS.name) }
                    ) {
                        Text("Unload Scripts")
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



                    LazyColumn(state = scrollState) {
                        items(messages) { message ->
                            SelectionContainer {
                                Text(text = message)
                            }
                        }
                    }


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
