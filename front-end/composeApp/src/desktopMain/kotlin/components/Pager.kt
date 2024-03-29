@file:OptIn(ExperimentalFoundationApi::class)

package components

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.PagerState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import io.socket.client.Socket
import kotlinx.coroutines.launch
import models.Application
import models.Device
import network.SocketEvents
import scripts.ScriptScreen


@Composable
fun PagerArea(
    pagerState: PagerState,
    partitionedApplications: MutableState<Pair<List<Application>, List<Application>>>,
    selectedDevice: Device,
    socket: Socket,
    selectedApp: Application,
    onAppSelected: (Application) -> Unit = {}
) {

    val scope = rememberCoroutineScope()

    HorizontalPager(
        userScrollEnabled = false,
        state = pagerState
    ) { page ->
        when (page) {
            Pages.APPS.index -> {
                ApplicationsComponent(
                    partitionedApplications.value,
                    selectedDevice,
                    socket,
                    onAppSelected = {
                        onAppSelected(it)
                        scope.launch {
                            pagerState.animateScrollToPage(1)
                        }
                    }
                )
            }

            Pages.SCRIPT.index -> {
                ScriptScreen(socket, selectedDevice, selectedApp,
                    onBack = {
                        socket.emit(SocketEvents.UNLOAD_SCRIPTS.name)
                        socket.emit(SocketEvents.GET_APPS.name, selectedDevice.deviceDetails.id)
                        scope.launch {
                            pagerState.animateScrollToPage(Pages.APPS.index)
                        }
                    })
            }

            else -> {
                Text(modifier = Modifier.fillMaxSize(), text = "others")
            }
        }
    }

}