package applications

import androidx.compose.desktop.ui.tooling.preview.Preview
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.Surface
import androidx.compose.material.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import models.Application


@Composable
fun ApplicationsArea(
    offlineApps: List<Application>,
    activeApps: List<Application>,
    onApplicationClicked: (Application) -> Unit
) {

    // TODO: add search and filter

    LazyColumn(modifier = Modifier.fillMaxWidth()) {
        item { Text("Active Apps") }
        items(activeApps) { app ->
            ApplicationItem(app) {
                onApplicationClicked(app)
            }
        }

        item { Text("Offline Apps") }

        items(offlineApps) { app ->
            ApplicationItem(app) {
                onApplicationClicked(app)
            }
        }

    }

}

@Composable
fun ApplicationItem(app: Application = Application(), onClick: () -> Unit = {}) {
    Surface(
        modifier = Modifier.padding(vertical = 8.dp).clickable { onClick() },
        shape = RoundedCornerShape(4.dp),
        elevation = 4.dp,
        color = Color.White
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 16.dp),
            horizontalArrangement = Arrangement.Start,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(app.name, fontWeight = FontWeight.Bold, color = Color(0XFF9595b3))
                Text(app.identifier, fontWeight = FontWeight.Light, color = Color(0XFF9595b3), fontSize = 14.sp)
                Text(app.pid.toString(), fontWeight = FontWeight.Light, color = Color(0XFF9595b3))
            }
            Spacer(modifier = Modifier.width(16.dp))

        }
    }
}
