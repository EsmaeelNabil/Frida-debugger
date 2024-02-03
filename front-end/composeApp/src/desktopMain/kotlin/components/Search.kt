package components

import LocalSocket
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import models.Device
import network.SocketEvents


@OptIn(ExperimentalFoundationApi::class)
@Composable
fun SearchArea(
    modifier: Modifier = Modifier,
    selectedDevice: Device,
) {

    val socket = LocalSocket.current

    SearchApplications(
        modifier = modifier,
        onSearch = {
            socket.emit(
                SocketEvents.GET_APPS.name,
                selectedDevice.deviceDetails.id, it
            )
        }
    )

}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SearchApplications(
    modifier: Modifier = Modifier,
    onSearch: (String) -> Unit
) {
    var text by remember { mutableStateOf("") }
    var active by remember { mutableStateOf(false) }
    val searchHistory = remember { mutableStateListOf("") }

    SearchBar(
        modifier = modifier,
        query = text,
        onQueryChange = {
            text = it
            onSearch(it)
        },
        onSearch = {
            active = false
            if (searchHistory.contains(it).not())
                searchHistory.add(it)
            onSearch(it)
        },
        active = false,
        onActiveChange = {
            active = it
        },
        placeholder = {
            Text(text = "Ex: Camera", fontWeight = FontWeight.Thin)
        },
        leadingIcon = {
            Icon(imageVector = Icons.Default.Search, contentDescription = "Search icon")
        },
        trailingIcon = {
            if (active) {
                Icon(
                    modifier = Modifier.clickable {
                        if (text.isNotEmpty()) {
                            text = ""
                        } else {
                            active = false
                        }
                    },
                    imageVector = Icons.Default.Close,
                    contentDescription = "Close icon"
                )
            }
        },
    ) {

    }

}
