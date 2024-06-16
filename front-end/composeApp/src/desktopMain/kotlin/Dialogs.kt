import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.window.AwtWindow
import androidx.compose.ui.window.FrameWindowScope
import androidx.compose.ui.window.WindowScope
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import java.awt.FileDialog
import java.io.File
import java.nio.file.Path
import javax.swing.JOptionPane

/**
 * This function displays a file dialog.
 *
 * @param title The title of the dialog.
 * @param isLoad A flag to indicate whether the dialog is for loading a file.
 * @param onResult The action to be performed when the dialog is closed.
 *
 * Example usage:
 * ```kotlin
 * FileDialog(
 *     title = "Choose a file",
 *     isLoad = true,
 *     onResult = { result -> /* action to perform with the result */ }
 * )
 * ```
 */
@Composable
fun FrameWindowScope.FileDialog(
    title: String,
    isLoad: Boolean,
    onResult: (result: Path?) -> Unit
) = AwtWindow(
    create = {
        object : FileDialog(window, "Choose a file", if (isLoad) LOAD else SAVE) {
            override fun setVisible(value: Boolean) {
                super.setVisible(value)
                if (value) {
                    if (file != null) {
                        onResult(File(directory).resolve(file).toPath())
                    } else {
                        onResult(null)
                    }
                }
            }
        }.apply {
            this.title = title
        }
    },
    dispose = FileDialog::dispose
)

/**
 * This function displays a message dialog.
 *
 * @param title The title of the dialog.
 * @param message The message to be displayed.
 *
 * Example usage:
 * ```kotlin
 * MessageDialog(
 *     title = "Information",
 *     message = "This is an information message."
 * )
 * ```
 */
@OptIn(DelicateCoroutinesApi::class)
@Composable
fun WindowScope.YesNoCancelDialog(
    title: String,
    message: String,
    onResult: (result: AlertDialogResult) -> Unit
) {
    DisposableEffect(Unit) {
        val job = GlobalScope.launch(Dispatchers.Default) {
            val resultInt = JOptionPane.showConfirmDialog(
                window, message, title, JOptionPane.YES_NO_CANCEL_OPTION
            )
            val result = when (resultInt) {
                JOptionPane.YES_OPTION -> AlertDialogResult.Yes
                JOptionPane.NO_OPTION -> AlertDialogResult.No
                else -> AlertDialogResult.Cancel
            }
            onResult(result)
        }

        onDispose {
            job.cancel()
        }
    }
}

/**
 * This function displays a message dialog.
 *
 * @param title The title of the dialog.
 * @param message The message to be displayed.
 *
 * Example usage:
 * ```kotlin
 * MessageDialog(
 *     title = "Information",
 *     message = "This is an information message."
 * )
 * ```
 */
enum class AlertDialogResult {
    Yes, No, Cancel
}