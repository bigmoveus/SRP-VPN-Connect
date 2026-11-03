package tr.com.srp.vpn

import android.content.Intent
import androidx.compose.animation.core.animate
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.Orientation
import androidx.compose.foundation.gestures.draggable
import androidx.compose.foundation.gestures.rememberDraggableState
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.input.nestedscroll.NestedScrollConnection
import androidx.compose.ui.input.nestedscroll.NestedScrollSource
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.Velocity
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.FileProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.math.max
import kotlin.math.roundToInt

/** The Connection Log, opened by tapping the status text: a sheet over the home screen that closes when dragged down, as on iOS. */
@Composable
fun LogScreen(onClose: () -> Unit) {
    val colors = LocalIosColors.current
    val context = LocalContext.current
    val file = remember { ConnectionLog.file(context) }
    var lines by remember { mutableStateOf(emptyList<String>()) }
    var refreshes by remember { mutableIntStateOf(0) }
    val list = rememberLazyListState()
    val scope = rememberCoroutineScope()
    var dragged by remember { mutableFloatStateOf(0f) }
    val closeDistance = with(LocalDensity.current) { 120.dp.toPx() }

    fun settle() {
        if (dragged > closeDistance) onClose() else scope.launch { animate(dragged, 0f) { value, _ -> dragged = value } }
    }

    // Pulling down past the top of the text moves the sheet.
    val pull = remember {
        object : NestedScrollConnection {
            override fun onPreScroll(available: Offset, source: NestedScrollSource): Offset {
                if (dragged <= 0f || available.y >= 0f) return Offset.Zero
                val used = max(available.y, -dragged)
                dragged += used
                return Offset(0f, used)
            }

            override fun onPostScroll(consumed: Offset, available: Offset, source: NestedScrollSource): Offset {
                if (available.y <= 0f || source != NestedScrollSource.UserInput) return Offset.Zero
                dragged += available.y
                return Offset(0f, available.y)
            }

            override suspend fun onPreFling(available: Velocity): Velocity {
                if (dragged <= 0f) return Velocity.Zero
                settle()
                return available
            }
        }
    }

    LaunchedEffect(refreshes) {
        val level = listOf("Normal", "Expert", "Debug")[AppModel.selected?.logLevel ?: 0]
        val log = withContext(Dispatchers.IO) { if (file.exists()) file.readText() else "" }
        lines = listOf("# srptunnel.log — log level: $level", "") + log.trimEnd('\n').ifEmpty { "(no log yet — connect once to produce one)" }.split('\n')
    }
    LaunchedEffect(lines) {
        if (lines.isNotEmpty()) list.scrollToItem(lines.lastIndex)
    }

    Column(
        Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .padding(top = 10.dp)
            .offset { IntOffset(0, dragged.roundToInt()) }
            .clip(RoundedCornerShape(topStart = 16.dp, topEnd = 16.dp))
            .background(colors.plainBackground)
            .nestedScroll(pull),
    ) {
        Box(
            Modifier.draggable(
                rememberDraggableState { delta -> dragged = max(0f, dragged + delta) },
                Orientation.Vertical,
                onDragStopped = { settle() },
            ),
        ) {
            NavBar(
                "Connection Log",
                colors.plainBackground,
                right = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        LogAction(Glyph.Trash, "Clear") {
                            file.delete()
                            file.createNewFile()
                            refreshes++
                        }
                        LogAction(Glyph.Share, "Share") {
                            val uri = FileProvider.getUriForFile(context, context.packageName + ".files", file.also { if (!it.exists()) it.createNewFile() })
                            val send = Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_STREAM, uri).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                            context.startActivity(Intent.createChooser(send, null))
                        }
                        LogAction(Glyph.Refresh, "Refresh") { refreshes++ }
                    }
                },
            )
        }
        // One text per line: the log can be 2 MB, which one text would lay out as a whole.
        SelectionContainer(Modifier.weight(1f).fillMaxWidth().navigationBarsPadding()) {
            LazyColumn(Modifier.fillMaxSize().padding(horizontal = 8.dp), list) {
                items(lines) { line ->
                    Label(line, IosText.caption.copy(fontSize = 11.sp, lineHeight = 14.sp, fontFamily = FontFamily.Monospace))
                }
            }
        }
    }
}

@Composable
private fun LogAction(glyph: Glyph, description: String, onClick: () -> Unit) {
    Box(Modifier.size(40.dp).clickable(onClickLabel = description, onClick = onClick).semantics { contentDescription = description }, contentAlignment = Alignment.Center) {
        GlyphIcon(glyph, LocalIosColors.current.blue, 22.dp)
    }
}
