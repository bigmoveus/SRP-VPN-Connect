package tr.com.srp.vpn

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.io.File
import java.io.RandomAccessFile

private const val LOG_BYTES_SHOWN = 64 * 1024L

class MainActivity : ComponentActivity() {
    private val vpnConsent = registerForActivityResult(StartActivityForResult()) { result ->
        if (result.resultCode == RESULT_OK) send(WaterWallVpnService.ACTION_CONNECT)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        val nodesFile = WaterWallVpnService.nodesFile(this)
        val savedNodes = if (nodesFile.exists()) nodesFile.readText() else ""
        val logFile = WaterWallVpnService.logFile(this)
        setContent {
            MaterialTheme {
                Surface {
                    ConnectionScreen(
                        savedNodes = savedNodes,
                        logFile = logFile,
                        onConnect = { nodes ->
                            nodesFile.writeText(nodes)
                            connect()
                        },
                        onDisconnect = { send(WaterWallVpnService.ACTION_DISCONNECT) },
                    )
                }
            }
        }
    }

    private fun connect() {
        val consent = VpnService.prepare(this)
        if (consent != null) vpnConsent.launch(consent) else send(WaterWallVpnService.ACTION_CONNECT)
    }

    private fun send(action: String) {
        startService(Intent(this, WaterWallVpnService::class.java).setAction(action))
    }
}

/** The end of the file from a line start, read without loading a log that may have grown large. */
private fun File.tail(bytes: Long): String = RandomAccessFile(this, "r").use { file ->
    val start = maxOf(0L, file.length() - bytes)
    file.seek(start)
    val buffer = ByteArray((file.length() - start).toInt())
    file.readFully(buffer)
    String(buffer).let { if (start > 0) it.substringAfter('\n') else it }
}

@Composable
private fun ConnectionScreen(
    savedNodes: String,
    logFile: File,
    onConnect: (String) -> Unit,
    onDisconnect: () -> Unit,
) {
    var nodes by remember { mutableStateOf(savedNodes) }
    var log by remember { mutableStateOf("") }
    val running by WaterWallVpnService.running.collectAsState()
    val logScroll = rememberScrollState()
    val mono = TextStyle(fontFamily = FontFamily.Monospace, fontSize = 11.sp)

    LaunchedEffect(Unit) {
        while (true) {
            log = withContext(Dispatchers.IO) { if (logFile.exists()) logFile.tail(LOG_BYTES_SHOWN) else "" }
            delay(1000)
        }
    }
    LaunchedEffect(log) { logScroll.scrollTo(logScroll.maxValue) }

    Column(
        modifier = Modifier.fillMaxSize().safeDrawingPadding().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        OutlinedTextField(
            value = nodes,
            onValueChange = { nodes = it },
            label = { Text("Client nodes JSON") },
            textStyle = mono,
            enabled = !running,
            modifier = Modifier.fillMaxWidth().weight(1f),
        )
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(onClick = { onConnect(nodes) }, enabled = !running && nodes.isNotBlank()) { Text("Connect") }
            OutlinedButton(onClick = onDisconnect, enabled = running) { Text("Disconnect") }
        }
        SelectionContainer(modifier = Modifier.fillMaxWidth().weight(1f).verticalScroll(logScroll)) {
            Text(text = log.ifEmpty { "The log appears here after you connect." }, style = mono)
        }
    }
}
