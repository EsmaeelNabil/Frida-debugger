@file:OptIn(ExperimentalFoundationApi::class, ExperimentalFoundationApi::class)

package components

import LocalSocket
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.pager.PagerState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.DrawerState
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import models.Device
import network.SocketEvents
import setHorizontalGradient

@Composable
fun TopBar(
    modifier: Modifier,
    pagerState: PagerState,
    selectedDevice: Device
) {
    val socket = LocalSocket.current
    if (pagerState.currentPage == Pages.APPS.index) {
        Row(
            modifier = modifier,
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.Center
        ) {

            SearchArea(
                modifier = Modifier.weight(0.9f)
                    .padding(bottom = 8.dp, start = 8.dp),
                selectedDevice = selectedDevice
            )

            IconButton(
                modifier = Modifier.weight(0.1f).padding(end = 8.dp),
                onClick = {
                    socket.emit(
                        SocketEvents.GET_APPS.name,
                        selectedDevice.deviceDetails.id
                    )
                }) {
                Icon(
                    Icons.Filled.Refresh,
                    null,
                    modifier = Modifier.size(24.dp),
                    tint = Color.White
                )
            }
        }
    }

}