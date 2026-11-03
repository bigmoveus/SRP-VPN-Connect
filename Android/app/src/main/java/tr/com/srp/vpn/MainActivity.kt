package tr.com.srp.vpn

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import kotlinx.coroutines.delay

/** Where screens send their short messages and alerts. */
class UiHost {
    var toast by mutableStateOf<Toast?>(null)
    var alert by mutableStateOf<Pair<String, String?>?>(null)

    class Toast(val text: String, val milliseconds: Long)

    fun showToast(text: String, milliseconds: Long = 2000) {
        toast = Toast(text, milliseconds)
    }

    fun showAlert(title: String, message: String?) {
        alert = title to message
    }
}

val LocalUi = staticCompositionLocalOf { UiHost() }

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        AppModel.attach(applicationContext)
        setContent {
            IosTheme {
                App()
            }
        }
    }
}

private sealed interface Modal {
    data class Editor(val profile: Profile?) : Modal

    data object Log : Modal
}

@Composable
private fun App() {
    val context = LocalContext.current
    val ui = remember { UiHost() }
    var modal by remember { mutableStateOf<Modal?>(null) }
    var pendingConnect by rememberSaveable { mutableStateOf<String?>(null) }
    val status by VpnState.status.collectAsState()

    fun send(action: String, profileId: String? = null) {
        context.startService(Intent(context, WaterWallVpnService::class.java).setAction(action).putExtra(WaterWallVpnService.EXTRA_PROFILE, profileId))
    }

    val consent = rememberLauncherForActivityResult(StartActivityForResult()) { result ->
        val profileId = pendingConnect
        pendingConnect = null
        if (result.resultCode == Activity.RESULT_OK && profileId != null) send(WaterWallVpnService.ACTION_CONNECT, profileId)
    }

    val focus = LocalFocusManager.current
    CompositionLocalProvider(LocalUi provides ui) {
        Box(
            Modifier.fillMaxSize().pointerInput(Unit) {
                awaitEachGesture {
                    val down = awaitFirstDown(requireUnconsumed = false, pass = PointerEventPass.Initial)
                    val edited = EditedField.bounds
                    if (edited != null && !edited.contains(down.position)) focus.clearFocus()
                }
            },
        ) {
            HomeScreen(
                status = status,
                onPower = {
                    if (status != VpnState.Status.Disconnected) {
                        send(WaterWallVpnService.ACTION_DISCONNECT)
                    } else {
                        val selected = AppModel.selected
                        if (selected == null || (selected.server.isEmpty() && !ChainConfig.isDirect(selected.configuration))) {
                            ui.showToast("Add a profile first (tap +)")
                        } else {
                            val request = VpnService.prepare(context)
                            if (request != null) {
                                pendingConnect = selected.nodeId
                                consent.launch(request)
                            } else {
                                send(WaterWallVpnService.ACTION_CONNECT, selected.nodeId)
                            }
                        }
                    }
                },
                onAdd = { modal = Modal.Editor(null) },
                onEdit = { profile -> modal = Modal.Editor(profile) },
                onHelp = { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://srpconnect.app"))) },
                onStatusTap = { modal = Modal.Log },
            )
            // The log is a sheet over the home screen, as on iOS.
            AnimatedVisibility(visible = modal is Modal.Log, enter = fadeIn(tween(300)), exit = fadeOut(tween(250))) {
                Box(Modifier.fillMaxSize().background(Color.Black.copy(alpha = 0.35f)).clickable(remember { MutableInteractionSource() }, null) {})
            }
            AnimatedVisibility(
                visible = modal != null,
                enter = slideInVertically(tween(300)) { it },
                exit = slideOutVertically(tween(250)) { it },
            ) {
                // Keeps showing while the sheet slides away.
                var shown by remember { mutableStateOf(modal) }
                LaunchedEffect(modal) { if (modal != null) shown = modal }
                when (val current = shown) {
                    is Modal.Editor -> ProfileEditor(current.profile, onClose = { modal = null }, onSave = { AppModel.put(it); modal = null })
                    Modal.Log -> LogScreen(onClose = { modal = null })
                    null -> Unit
                }
            }
            ui.toast?.let { toast ->
                LaunchedEffect(toast) {
                    delay(toast.milliseconds)
                    ui.toast = null
                }
                ToastBubble(toast.text, Modifier.align(Alignment.Center))
            }
            ui.alert?.let { (title, message) ->
                IosAlert(title, message) { ui.alert = null }
            }
        }
    }
    BackHandler(modal != null) { modal = null }
}
