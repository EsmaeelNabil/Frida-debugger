import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalWindowInfo
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import kotlin.io.path.readText


@Composable
fun ScriptInputDialog(
    initialScript: String = "",
    onDismissRequest: () -> Unit = {},
    onConfirmation: (String) -> Unit = { _ -> }
) {

    val window = LocalWindowFrameScope.current
    var currentScript by remember { mutableStateOf(initialScript) }
    var openFilePicker by remember { mutableStateOf(false) }

    if (openFilePicker) {
        window.FileDialog(
            title = "Open Script",
            isLoad = true,
            onResult = { result ->
                if (result != null) {
                    currentScript = result.readText()
                }
            }
        )
    }



    Dialog(onDismissRequest = onDismissRequest) {
        Card(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp),
            shape = RoundedCornerShape(24.dp),
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize(),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {


                Surface(
                    modifier = Modifier.weight(1f).fillMaxSize(),
                    shape = RoundedCornerShape(24.dp),
                ) {
                    BasicTextField(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(16.dp),
                        value = currentScript,
                        onValueChange = { currentScript = it },
                    )
                }

                Text(
                    text = "Write or paste your script here.",
                    modifier = Modifier.padding(16.dp),
                )

                Row(
                    modifier = Modifier
                        .fillMaxWidth(),
                    horizontalArrangement = Arrangement.Center,
                ) {
                    TextButton(
                        onClick = { onDismissRequest() },
                        modifier = Modifier.padding(8.dp),
                    ) {
                        Text("Dismiss")
                    }

                    TextButton(
                        onClick = { openFilePicker = true },
                        modifier = Modifier.padding(8.dp),
                    ) {
                        Text("Load from file")
                    }
                    TextButton(
                        onClick = {
                            onConfirmation(currentScript)
                            onDismissRequest()
                        },
                        modifier = Modifier.padding(8.dp),
                    ) {
                        Text("Confirm")
                    }
                }
            }
        }
    }

}