@file:OptIn(ExperimentalMaterialApi::class)

package devices

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Done
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import models.Device


@Composable
fun DevicesArea(
    devices: List<Device> = listOf(),
    selectedDevice: Device,
    onDeviceSelected: (Device) -> Unit,
    onFetchApps: (Device) -> Unit = {}
) {
    Column {
        Surface(
            shape = RoundedCornerShape(26.dp),
            elevation = 2.dp
        ) {
            Row {


                LazyRow(
                    modifier = Modifier.padding(vertical = 4.dp, horizontal = 8.dp)
                ) {
                    items(devices, key = { item: Device -> item.deviceDetails.name }) { device ->
                        DeviceChip(
                            modifier = Modifier.padding(8.dp),
                            selected = selectedDevice.deviceDetails.id == device.deviceDetails.id,
                            name = device.deviceDetails.name
                        ) {
                            onDeviceSelected(device)
                            onFetchApps(device)
                        }
                    }
                }

            }
        }
    }

}


@Composable
fun DeviceChip(
    modifier: Modifier = Modifier,
    name: String,
    selected: Boolean,
    onClick: () -> Unit
) {

    FilterChip(
        modifier = modifier,
        selected = selected,
        onClick = { onClick() },
        leadingIcon = if (selected) {
            {
                Icon(
                    imageVector = Icons.Filled.Done,
                    contentDescription = "Done icon",
                    modifier = Modifier.size(24.dp)
                )
            }
        } else {
            null
        },
    ) {
        Text(name)
    }
}