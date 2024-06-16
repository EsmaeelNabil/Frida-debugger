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

/**
 * This function displays a control icon for the application.
 * @param modifier The modifier to be applied to the control icon.
 * @param containerSize The size of the container of the control icon.
 * @param iconSize The size of the icon.
 * @param icon The icon to be displayed.
 * @param onClick The action to be performed when the control icon is clicked.
 *
 * Example usage:
 * ```kotlin
 * ControlIcon(
 *     modifier = Modifier,
 *     containerSize = 24.dp,
 *     iconSize = 10.dp,
 *     icon = Icons.Default.Close,
 *     onClick = { }
 * )
 */
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