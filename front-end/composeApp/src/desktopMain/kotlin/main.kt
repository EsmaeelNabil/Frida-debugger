import androidx.compose.ui.window.application


fun main() = application {
    FridaApp(onCloseRequest = ::exitApplication)
}