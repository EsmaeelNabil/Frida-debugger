@file:OptIn(ExperimentalMaterialApi::class)

package components

import androidx.compose.foundation.layout.*
import androidx.compose.material.Chip
import androidx.compose.material.ExperimentalMaterialApi
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import emptyString
import models.Device
import models.DeviceDetails


@OptIn(ExperimentalMaterialApi::class)
@Composable
fun DrawerComponent(
    modifier: Modifier,
    devices: List<Device>,
    selectedDevice: Device,
    onMainApplicationClose: () -> Unit = {},
    onMainApplicationMinimize: () -> Unit = {},
    onDeviceSelected: (Device) -> Unit = {}
) {

    val shimmerList = remember {
        mutableStateOf(List(4) {
            Device(DeviceDetails(name = emptyString))
        })
    }

    val listToRender = devices.ifEmpty { shimmerList.value }

    Box {

        Column(
            modifier = Modifier.align(Alignment.CenterStart)
                .padding(start = 8.dp)
        ) {
            ControlIcon(
                containerSize = 24.dp,
                iconSize = 15.dp,
                icon = Icons.Default.Close,
                onClick = { onMainApplicationClose() }
            )
            Spacer(modifier = Modifier.height(4.dp))
            ControlIcon(
                containerSize = 24.dp,
                iconSize = 15.dp,
                icon = Icons.Default.ArrowDownward,
                onClick = { onMainApplicationMinimize() }
            )
        }

        Surface(
            modifier.align(Alignment.TopCenter),
            shape = MaterialTheme.shapes.extraLarge,
            shadowElevation = 3.dp
        ) {
            Row(modifier = Modifier.padding(16.dp)) {
                listToRender.forEach { device ->
                    val selected = selectedDevice.deviceDetails.name == device.deviceDetails.name
                    Chip(
                        modifier = Modifier.padding(horizontal = 8.dp).wrapContentWidth(),
                        onClick = {
                            onDeviceSelected(device)
                        }
                    ) {
                        val weight =
                            if (device.deviceDetails.type == "usb")
                                FontWeight.Medium
                            else
                                FontWeight.Thin
                        Text(
                            text = device.deviceDetails.name,
                            fontWeight = weight,
                            color = if (selected)
                                Color.Blue
                            else
                                Color.Black
                        )
                    }
                }
            }
        }
    }

}
