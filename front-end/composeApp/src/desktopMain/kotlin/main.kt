import androidx.compose.ui.window.application

/**
 * The main entry point for the application.
 *
 * This function sets up the application and specifies the main composable to be displayed.
 * It also handles the application close request by calling the provided [exitApplication] function.
 */
fun main() = application {
    FridaApp(onCloseRequest = ::exitApplication)
}