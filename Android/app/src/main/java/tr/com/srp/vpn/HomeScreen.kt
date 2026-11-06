package tr.com.srp.vpn

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.Orientation
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.gestures.draggable
import androidx.compose.foundation.gestures.rememberDraggableState
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.material3.pulltorefresh.rememberPullToRefreshState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch
import kotlin.math.roundToInt

@Composable
fun HomeScreen(
    status: VpnState.Status,
    onPower: () -> Unit,
    onAdd: () -> Unit,
    onEdit: (Profile) -> Unit,
    onHelp: () -> Unit,
    onStatusTap: () -> Unit,
) {
    val colors = LocalIosColors.current
    val ui = LocalUi.current
    val context = LocalContext.current
    val version = remember { context.packageManager.getPackageInfo(context.packageName, 0).versionName }
    val wasConnecting = remember { booleanArrayOf(false) }

    // The status drives the rest of the screen, as PDVPNManager's notification does on iOS.
    LaunchedEffect(status) {
        if (status != VpnState.Status.Connected) AppModel.cancelConnectedPing()
        when (status) {
            VpnState.Status.Connected -> {
                wasConnecting[0] = false
                AppModel.measureConnected()
            }
            VpnState.Status.Connecting -> wasConnecting[0] = true
            VpnState.Status.Disconnected -> {
                if (wasConnecting[0]) {
                    VpnState.lastError?.let { (message, time) ->
                        if (System.currentTimeMillis() - time <= 30000) {
                            VpnState.lastError = null
                            ui.showAlert("Connection Failed", message)
                        }
                    }
                }
                wasConnecting[0] = false
            }
        }
    }

    Column(Modifier.fillMaxSize().background(colors.groupedBackground).statusBarsPadding().navigationBarsPadding()) {
        HomeHeader(status, onPower, onStatusTap, onHelp, onAdd) {
            val selected = AppModel.selected
            when {
                status == VpnState.Status.Connected -> ui.showToast("Disconnect the VPN before editing this profile")
                selected == null -> ui.showToast("Select a profile first (or add one with +)")
                else -> onEdit(selected)
            }
        }
        ProfileList(status, Modifier.weight(1f))
        Label("version $version", IosText.caption, colors.tertiaryLabel, Modifier.fillMaxWidth().padding(top = 4.dp, bottom = 8.dp), textAlign = TextAlign.Center)
    }
}

@Composable
private fun HomeHeader(
    status: VpnState.Status,
    onPower: () -> Unit,
    onStatusTap: () -> Unit,
    onHelp: () -> Unit,
    onAdd: () -> Unit,
    onEdit: () -> Unit,
) {
    val colors = LocalIosColors.current
    val target = when (status) {
        VpnState.Status.Connected -> colors.green
        VpnState.Status.Connecting -> colors.blue
        VpnState.Status.Disconnected -> colors.gray
    }
    val tint by animateColorAsState(target, tween(250))
    val text = when (status) {
        VpnState.Status.Connected -> "Connected"
        VpnState.Status.Connecting -> "Connecting…"
        VpnState.Status.Disconnected -> "Disconnected"
    }
    // Light pulse while connecting.
    val scale = if (status == VpnState.Status.Connecting) {
        rememberInfiniteTransition(label = "connecting").animateFloat(1f, 1.06f, infiniteRepeatable(tween(700), RepeatMode.Reverse), label = "scale").value
    } else {
        1f
    }
    Column(Modifier.fillMaxWidth().padding(top = 24.dp, bottom = 20.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Label("SRP VPN Connect", IosText.title2, textAlign = TextAlign.Center)
        Box(
            Modifier
                .size(96.dp)
                .scale(scale)
                .clip(CircleShape)
                .background(tint.copy(alpha = 0.12f))
                .clickable(onClickLabel = "Connect or disconnect", role = Role.Button, onClick = onPower)
                .semantics { contentDescription = "Power" },
            contentAlignment = Alignment.Center,
        ) {
            GlyphIcon(Glyph.Power, tint, 50.dp)
        }
        Label(text, IosText.headline, tint, Modifier.clickable(onClickLabel = "Open the connection log", onClick = onStatusTap))
        Row(horizontalArrangement = Arrangement.spacedBy(24.dp), verticalAlignment = Alignment.CenterVertically) {
            ToolbarButton(Glyph.Edit, "Edit profile", onEdit)
            ToolbarButton(Glyph.Help, "Help", onHelp)
            ToolbarButton(Glyph.Plus, "Add profile", onAdd)
        }
    }
}

@Composable
private fun ToolbarButton(glyph: Glyph, description: String, onClick: () -> Unit) {
    Box(
        Modifier.size(44.dp).clip(CircleShape).clickable(onClickLabel = description, role = Role.Button, onClick = onClick).semantics { contentDescription = description },
        contentAlignment = Alignment.Center,
    ) {
        GlyphIcon(glyph, LocalIosColors.current.secondaryLabel, 25.dp)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ProfileList(status: VpnState.Status, modifier: Modifier) {
    val colors = LocalIosColors.current
    val ui = LocalUi.current
    val refreshState = rememberPullToRefreshState()
    val open = remember { OpenSwipe() }
    PullToRefreshBox(
        isRefreshing = AppModel.pinging,
        onRefresh = { AppModel.pingAll { ui.showToast(it, 2500) } },
        modifier = modifier.fillMaxWidth().pointerInput(Unit) {
            awaitEachGesture {
                awaitFirstDown(requireUnconsumed = false, pass = PointerEventPass.Main)
                if (open.id != null && !open.touchedOpenRow) open.id = null
                open.touchedOpenRow = false
            }
        },
        state = refreshState,
        indicator = {
            val pulled = AppModel.pinging || refreshState.distanceFraction > 0f
            if (pulled) {
                Column(Modifier.align(Alignment.TopCenter).padding(top = 4.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                    CircularProgressIndicator(Modifier.size(20.dp), color = colors.gray, strokeWidth = 2.dp)
                    Label(AppModel.pullTitle, IosText.caption, colors.secondaryLabel, Modifier.padding(top = 4.dp))
                }
            }
        },
    ) {
        if (AppModel.profiles.isEmpty()) {
            // Still scrollable, so that the empty list can be pulled like iOS's table.
            LazyColumn(Modifier.fillMaxSize()) {
                item {
                    Box(Modifier.fillParentMaxSize(), contentAlignment = Alignment.Center) {
                        Label("No profiles yet — tap + to add", IosText.callout, colors.secondaryLabel, textAlign = TextAlign.Center)
                    }
                }
            }
        } else {
            LazyColumn(Modifier.fillMaxSize()) {
                items(AppModel.profiles, key = { it.nodeId }) { profile -> ProfileRow(profile, status, open) }
            }
        }
    }
}

@Composable
private fun ProfileRow(profile: Profile, status: VpnState.Status, open: OpenSwipe) {
    val ui = LocalUi.current
    val colors = LocalIosColors.current
    val selected = AppModel.selectedId == profile.nodeId
    val milliseconds = AppModel.latencyMs[profile.nodeId]
    val latencyColor = when {
        milliseconds == null -> colors.secondaryLabel
        milliseconds < 0 || milliseconds >= 500 -> colors.red
        milliseconds < 200 -> colors.green
        else -> colors.orange
    }
    SwipeActions(
        id = profile.nodeId,
        open = open,
        onPing = { AppModel.pingProfile(profile) { ui.showToast(it, 2500) } },
        onDelete = {
            if (status != VpnState.Status.Disconnected) ui.showToast("Disconnect the VPN before deleting this profile")
            else AppModel.delete(profile)
        },
        onTap = { AppModel.selectedId = profile.nodeId },
    ) {
        Row(
            Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).background(colors.cell).padding(start = 14.dp, end = 14.dp, top = 10.dp, bottom = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Label(profile.desc.ifEmpty { profile.server.ifEmpty { profile.nodeName } }, IosText.headline, maxLines = 1)
                // iOS's home row: the chain summary for WaterWall, the server and port for SSTP
                Label(if (profile.isSstp) "${profile.server}:${profile.port}" else ChainConfig.summary(profile.configuration), IosText.subheadline, colors.secondaryLabel, maxLines = 1)
            }
            Spacer(Modifier.width(8.dp))
            Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Box(Modifier.clip(RoundedCornerShape(9.dp)).background(colors.blue.copy(alpha = 0.12f)).padding(horizontal = 8.dp, vertical = 3.dp)) {
                    Label(profile.nodeName, IosText.caption.copy(fontSize = 11.sp, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.SemiBold), colors.blue, maxLines = 1)
                }
                Label(AppModel.latencyText[profile.nodeId] ?: "Ping: —", IosText.caption, latencyColor, textAlign = TextAlign.Center, maxLines = 1)
            }
            Spacer(Modifier.width(10.dp))
            if (selected) SelectedMark(24.dp) else GlyphIcon(Glyph.Ring, colors.tertiaryLabel, 24.dp)
        }
    }
}

private const val FULL_SWIPE = 0.6f

/** Which row has its actions open; like iOS's table, one at a time, and the next touch elsewhere only closes them. */
private class OpenSwipe {
    var id by mutableStateOf<String?>(null)
    var touchedOpenRow = false
}

/** A row that shows a blue Ping button when swiped right and a red Delete button when swiped left; a long swipe runs it at once. */
@Composable
private fun SwipeActions(id: String, open: OpenSwipe, onPing: () -> Unit, onDelete: () -> Unit, onTap: () -> Unit, content: @Composable () -> Unit) {
    val colors = LocalIosColors.current
    val density = LocalDensity.current
    val actionWidth = with(density) { 84.dp.toPx() }
    val offset = remember { Animatable(0f) }
    val scope = rememberCoroutineScope()
    var rowWidth by remember { mutableIntStateOf(0) }
    fun close() {
        open.id = null
        scope.launch { offset.animateTo(0f) }
    }
    LaunchedEffect(open.id) {
        if (open.id != id && offset.value != 0f) offset.animateTo(0f)
    }
    Box(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 5.dp)
            .height(IntrinsicSize.Min)
            .onSizeChanged { rowWidth = it.width }
            .pointerInput(id) {
                awaitEachGesture {
                    val down = awaitFirstDown(requireUnconsumed = false, pass = PointerEventPass.Initial)
                    if (open.id == id) open.touchedOpenRow = true
                    else if (open.id != null) down.consume()
                }
            },
    ) {
        if (offset.value != 0f) {
            val ping = offset.value > 0
            Box(
                Modifier
                    .align(if (ping) Alignment.CenterStart else Alignment.CenterEnd)
                    .fillMaxHeight()
                    .width(with(density) { kotlin.math.abs(offset.value).toDp() })
                    .clip(RoundedCornerShape(12.dp))
                    .background(if (ping) colors.blue else colors.red)
                    .clickable(role = Role.Button, onClickLabel = if (ping) "Ping" else "Delete") {
                        close()
                        if (ping) onPing() else onDelete()
                    },
                contentAlignment = Alignment.Center,
            ) {
                Label(if (ping) "Ping" else "Delete", IosText.subheadline.copy(fontWeight = FontWeight.SemiBold), Color.White, maxLines = 1)
            }
        }
        Box(
            Modifier
                .offset { IntOffset(offset.value.roundToInt(), 0) }
                .draggable(
                    orientation = Orientation.Horizontal,
                    state = rememberDraggableState { delta -> scope.launch { offset.snapTo(offset.value + delta) } },
                    onDragStopped = {
                        if (kotlin.math.abs(offset.value) > rowWidth * FULL_SWIPE) {
                            open.id = null
                            if (offset.value > 0) onPing() else onDelete()
                            offset.animateTo(0f)
                        } else {
                            val target = if (offset.value > actionWidth / 2) actionWidth else if (offset.value < -actionWidth / 2) -actionWidth else 0f
                            open.id = if (target != 0f) id else null
                            offset.animateTo(target)
                        }
                    },
                )
                .clickable(remember { MutableInteractionSource() }, null) {
                    if (offset.value != 0f) close() else onTap()
                },
        ) {
            content()
        }
    }
}
