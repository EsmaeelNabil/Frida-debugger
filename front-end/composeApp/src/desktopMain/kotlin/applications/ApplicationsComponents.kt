package applications

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.Surface
import androidx.compose.material.Text
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
import models.Application


@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SearchApplications(
    modifier: Modifier = Modifier,
    onSearch: (String) -> Unit
) {
    var text by remember { mutableStateOf("") } // Query for SearchBar
    var active by remember { mutableStateOf(false) } // Active state for SearchBar
    val searchHistory = remember { mutableStateListOf("") }

    SearchBar(modifier = modifier,
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
            androidx.compose.material3.Text(text = "Enter an application name ex: Camera")
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
        }
    ) {

    }

}


@Composable
fun applicationsArea(
    offlineApps: List<Application>,
    activeApps: List<Application>,
    onApplicationClicked: (Application) -> Unit
) {

    // TODO: add search and filter

    LazyColumn(modifier = Modifier.fillMaxWidth().padding(24.dp)) {
        if (activeApps.isNotEmpty()) {
            item { Text("Active Apps", modifier = Modifier.padding(horizontal = 16.dp), fontWeight = FontWeight.Bold) }
            items(activeApps) { app ->
                ApplicationItem(app) {
                    onApplicationClicked(app)
                }
            }
        }

        if (offlineApps.isNotEmpty()) {
            item { Text("Offline Apps", modifier = Modifier.padding(horizontal = 16.dp), fontWeight = FontWeight.Bold) }
            items(offlineApps) { app ->
                ApplicationItem(app) {
                    onApplicationClicked(app)
                }
            }
        }


    }

}

@Composable
fun ApplicationItem(app: Application = Application(), onClick: () -> Unit = {}) {
    val appIsRunning = app.pid.toString() != "0"
    var showMore by remember { mutableStateOf(false) }
    Column {
        Row(
            modifier = Modifier.padding(horizontal = 16.dp),
            horizontalArrangement = Arrangement.Start,
            verticalAlignment = Alignment.CenterVertically
        ) {

            Surface(
                modifier = Modifier.weight(0.01f).size(20.dp).fillMaxHeight(),
                shape = CircleShape,
                elevation = 3.dp,
                color = if (appIsRunning.not()) Color.Red else Color.Green
            ) {}


            Surface(
                modifier = Modifier.fillMaxWidth().padding(16.dp).weight(1f)
                        then (Modifier.clickable { onClick() }),
                shape = RoundedCornerShape(20.dp),
                elevation = 3.dp,
                color = Color.White
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.padding(start = 16.dp)
                ) {
                    Column(modifier = Modifier.weight(1f).padding(8.dp)) {
                        Text(app.name, fontWeight = FontWeight.Bold, color = Color(0XFF9595b3))
                        Text(app.identifier, fontWeight = FontWeight.Light, color = Color(0XFF9595b3), fontSize = 14.sp)
                        Text(app.pid.toString(), fontWeight = FontWeight.Light, color = Color(0XFF9595b3))
                    }

                    IconButton(onClick = {
                        showMore = !showMore
                    }) {
                        Icon(Icons.Filled.ExpandMore, null)
                    }
                    Spacer(modifier = Modifier.width(16.dp))
                }
            }
        }
        AnimatedVisibility(showMore) {
            Column (modifier = Modifier.padding(horizontal = 24.dp)){
                Text(
                    "Build number : ${app.parameters.build}",
                    fontWeight = FontWeight.Thin,
                    color = Color(0XFF9595b3)
                )
                Text(
                    "Version number : ${app.parameters.version}",
                    fontWeight = FontWeight.Thin,
                    color = Color(0XFF9595b3)
                )
                Text(
                    "dataDir : ${app.parameters.dataDir}",
                    fontWeight = FontWeight.Thin,
                    color = Color(0XFF9595b3)
                )
                Text(
                    "started : ${app.parameters.started}",
                    fontWeight = FontWeight.Thin,
                    color = Color(0XFF9595b3)
                )
                Text(
                    "targetSdk : ${app.parameters.targetSdk}",
                    fontWeight = FontWeight.Thin,
                    color = Color(0XFF9595b3)
                )
                Text(
                    "debuggable : ${app.parameters.debuggable}",
                    fontWeight = FontWeight.Thin,
                    color = Color(0XFF9595b3)
                )
            }
        }
    }
}
