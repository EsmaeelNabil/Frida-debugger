package components

import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

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