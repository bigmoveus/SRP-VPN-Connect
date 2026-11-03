package tr.com.srp.vpn

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicText
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.composed
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.scale
import androidx.compose.ui.graphics.vector.PathParser
import androidx.compose.ui.layout.boundsInRoot
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties

// The look of the iOS app: its system colors and text styles, grouped lists, switches, segmented controls and round bar buttons.

@Immutable
class IosColors(
    val groupedBackground: Color,
    val cell: Color,
    val plainBackground: Color,
    val label: Color,
    val secondaryLabel: Color,
    val tertiaryLabel: Color,
    val separator: Color,
    val cellPressed: Color,
    val fill: Color,
    val segmentSelected: Color,
    val switchOff: Color,
    val barButton: Color,
    val blue: Color,
    val green: Color,
    val red: Color,
    val orange: Color,
    val gray: Color,
)

private val LightColors = IosColors(
    groupedBackground = Color(0xFFF2F2F7), cell = Color.White, plainBackground = Color.White, label = Color.Black,
    secondaryLabel = Color(0x993C3C43), tertiaryLabel = Color(0x4D3C3C43), separator = Color(0x4A3C3C43), cellPressed = Color(0xFFD1D1D6),
    fill = Color(0x1F767680), segmentSelected = Color.White, switchOff = Color(0x29787880), barButton = Color.White,
    blue = Color(0xFF007AFF), green = Color(0xFF34C759), red = Color(0xFFFF3B30), orange = Color(0xFFFF9500), gray = Color(0xFF8E8E93),
)

private val DarkColors = IosColors(
    groupedBackground = Color.Black, cell = Color(0xFF1C1C1E), plainBackground = Color.Black, label = Color.White,
    secondaryLabel = Color(0x99EBEBF5), tertiaryLabel = Color(0x4DEBEBF5), separator = Color(0x99545458), cellPressed = Color(0xFF2C2C2E),
    fill = Color(0x3D767680), segmentSelected = Color(0xFF636366), switchOff = Color(0x52787880), barButton = Color(0xFF2C2C2E),
    blue = Color(0xFF0A84FF), green = Color(0xFF30D158), red = Color(0xFFFF453A), orange = Color(0xFFFF9F0A), gray = Color(0xFF8E8E93),
)

val LocalIosColors = staticCompositionLocalOf { LightColors }

object IosText {
    val title2 = TextStyle(fontSize = 22.sp, lineHeight = 28.sp)
    val headline = TextStyle(fontSize = 17.sp, lineHeight = 22.sp, fontWeight = FontWeight.SemiBold)
    val body = TextStyle(fontSize = 17.sp, lineHeight = 22.sp)
    val callout = TextStyle(fontSize = 16.sp, lineHeight = 21.sp)
    val subheadline = TextStyle(fontSize = 15.sp, lineHeight = 20.sp)
    val footnote = TextStyle(fontSize = 13.sp, lineHeight = 18.sp)
    val caption = TextStyle(fontSize = 12.sp, lineHeight = 16.sp)
    val mono = FontFamily.Monospace
}

@Composable
fun IosTheme(content: @Composable () -> Unit) {
    val colors = if (isSystemInDarkTheme()) DarkColors else LightColors
    CompositionLocalProvider(LocalIosColors provides colors) { content() }
}

/** A line of text in the current colors. */
@Composable
fun Label(
    text: String,
    style: TextStyle = IosText.body,
    color: Color = LocalIosColors.current.label,
    modifier: Modifier = Modifier,
    maxLines: Int = Int.MAX_VALUE,
    textAlign: TextAlign = TextAlign.Unspecified,
) {
    BasicText(text, modifier, style.copy(color = color, textAlign = textAlign), maxLines = maxLines, overflow = if (maxLines == Int.MAX_VALUE) TextOverflow.Clip else TextOverflow.Ellipsis)
}

enum class Glyph(val path: String, val strokeWidth: Float = 1.9f) {
    Power("M12 3v9M7.2 6.2a8 8 0 1 0 9.6 0", 2.2f),
    Edit("M11 4.5H7a3 3 0 0 0-3 3v9.5a3 3 0 0 0 3 3h9.5a3 3 0 0 0 3-3V13M10 14l.6-2.6L18.9 3.1a1.5 1.5 0 0 1 2 2L12.6 13.4z"),
    Help("M12 2.75a9.25 9.25 0 1 0 0 18.5a9.25 9.25 0 1 0 0-18.5zM9.2 9.4a2.9 2.9 0 1 1 4.6 2.3c-1 .7-1.8 1.4-1.8 2.7M12 17.6v.01"),
    Plus("M12 4v16M4 12h16"),
    Close("M5.5 5.5l13 13M18.5 5.5l-13 13", 2.2f),
    Back("M15 4.5L7.5 12L15 19.5", 2.4f),
    Chevron("M9 4.5L16.5 12L9 19.5", 2.6f),
    Check("M4.5 12.5l5 5.5L19.5 6.5", 2.4f),
    Ring("M12 2.75a9.25 9.25 0 1 0 0 18.5a9.25 9.25 0 1 0 0-18.5z"),
    Refresh("M19.5 12a7.5 7.5 0 1 1-2.2-5.3L20 9.4M20 4v5.4h-5.4"),
    Share("M12 15V3M8 6.5L12 2.5l4 4M7.5 10H6a2 2 0 0 0-2 2v7.5a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V12a2 2 0 0 0-2-2h-1.5"),
    Trash("M4 6h16M9 6V4.5A1.5 1.5 0 0 1 10.5 3h3A1.5 1.5 0 0 1 15 4.5V6M6 6l1 14a1.5 1.5 0 0 0 1.5 1.5h7A1.5 1.5 0 0 0 17 20l1-14M10 10.5v7M14 10.5v7"),
    Search("M10.5 3.5a7 7 0 1 0 0 14a7 7 0 1 0 0-14zM15.6 15.6L21 21"),
    ClearMark("M8.5 8.5l7 7M15.5 8.5l-7 7", 2.2f),
}

/** One of the app's symbols, drawn to look like its SF Symbol. */
@Composable
fun GlyphIcon(glyph: Glyph, tint: Color, size: Dp, modifier: Modifier = Modifier) {
    val path = remember(glyph) { PathParser().parsePathString(glyph.path).toPath() }
    Canvas(modifier.size(size)) {
        val factor = this.size.width / 24f
        scale(factor, factor, Offset.Zero) {
            drawPath(path, tint, style = Stroke(width = glyph.strokeWidth, cap = StrokeCap.Round, join = StrokeJoin.Round))
        }
    }
}

/** The filled blue circle with a tick of a selected profile. */
@Composable
fun SelectedMark(size: Dp) {
    val colors = LocalIosColors.current
    Box(Modifier.size(size).clip(CircleShape).background(colors.blue), contentAlignment = Alignment.Center) {
        GlyphIcon(Glyph.Check, Color.White, size * 0.62f)
    }
}

/** A round bar button, like the ✕, back and ✓ of iOS. */
@Composable
fun RoundBarButton(glyph: Glyph, description: String, prominent: Boolean = false, onClick: () -> Unit) {
    val colors = LocalIosColors.current
    Box(
        Modifier
            .size(44.dp)
            .shadow(3.dp, CircleShape)
            .clip(CircleShape)
            .background(if (prominent) colors.blue else colors.barButton)
            .clickable(onClickLabel = description, role = Role.Button, onClick = onClick)
            .semantics { contentDescription = description },
        contentAlignment = Alignment.Center,
    ) {
        GlyphIcon(glyph, if (prominent) Color.White else colors.label, 20.dp)
    }
}

/** The title bar of a pushed screen: a round button on each side and the title between them. */
@Composable
fun NavBar(title: String, background: Color = LocalIosColors.current.groupedBackground, left: (@Composable () -> Unit)? = null, right: (@Composable () -> Unit)? = null) {
    Box(Modifier.fillMaxWidth().background(background).statusBarsPadding().height(68.dp).padding(horizontal = 16.dp)) {
        Box(Modifier.align(Alignment.CenterStart)) { left?.invoke() }
        Label(title, IosText.headline, modifier = Modifier.align(Alignment.Center).widthIn(max = 220.dp), maxLines = 1)
        Box(Modifier.align(Alignment.CenterEnd)) { right?.invoke() }
    }
}

/** The blue Save pill of the profile editor. */
@Composable
fun SaveButton(onClick: () -> Unit) {
    val colors = LocalIosColors.current
    Box(
        Modifier
            .height(44.dp)
            .shadow(3.dp, RoundedCornerShape(22.dp))
            .clip(RoundedCornerShape(22.dp))
            .background(colors.blue)
            .clickable(role = Role.Button, onClick = onClick)
            .padding(horizontal = 22.dp),
        contentAlignment = Alignment.Center,
    ) {
        Label("Save", IosText.headline, Color.White)
    }
}

class SectionScope {
    internal val rows = ArrayList<@Composable () -> Unit>()

    fun row(content: @Composable () -> Unit) {
        rows.add(content)
    }
}

/** A grouped table section: an optional uppercase header, white rows with hairlines, an optional note below. */
@Composable
fun Section(header: String? = null, footer: String? = null, content: SectionScope.() -> Unit) {
    val colors = LocalIosColors.current
    val rows = SectionScope().apply(content).rows
    if (header != null) {
        Label(header, IosText.subheadline.copy(fontWeight = FontWeight.SemiBold), colors.secondaryLabel, Modifier.padding(start = 16.dp, end = 16.dp, top = 24.dp, bottom = 8.dp))
    } else {
        Spacer(Modifier.height(32.dp))
    }
    Hairline()
    Column(Modifier.fillMaxWidth().background(colors.cell)) {
        rows.forEachIndexed { index, row ->
            row()
            if (index < rows.lastIndex) Hairline(Modifier.padding(start = 16.dp))
        }
    }
    Hairline()
    if (footer != null) {
        Label(footer, IosText.footnote.copy(fontSize = 14.sp, lineHeight = 19.sp), colors.secondaryLabel, Modifier.padding(start = 16.dp, end = 16.dp, top = 8.dp))
    }
}

@Composable
private fun Hairline(modifier: Modifier = Modifier) {
    Box(modifier.fillMaxWidth().height(0.5.dp).background(LocalIosColors.current.separator))
}

private val RowHeight = 52.dp

@Composable
private fun PressableRow(onClick: (() -> Unit)?, content: @Composable RowScope.() -> Unit) {
    val colors = LocalIosColors.current
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    Row(
        Modifier
            .fillMaxWidth()
            .heightIn(min = RowHeight)
            .background(if (pressed) colors.cellPressed else colors.cell)
            .then(if (onClick != null) Modifier.clickable(interaction, null, onClick = onClick) else Modifier)
            .padding(horizontal = 16.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        content()
    }
}

/** A title with a value on the right, and a disclosure mark when it opens something. */
@Composable
fun ValueRow(title: String, value: String? = null, disclosure: Boolean = true, enabled: Boolean = true, onClick: (() -> Unit)? = null) {
    val colors = LocalIosColors.current
    PressableRow(if (enabled) onClick else null) {
        Label(title, color = if (enabled) colors.label else colors.tertiaryLabel, modifier = Modifier.weight(1f), maxLines = 2)
        Spacer(Modifier.width(8.dp))
        if (value != null) Label(value, color = if (enabled) colors.secondaryLabel else colors.tertiaryLabel, textAlign = TextAlign.End, maxLines = 2, modifier = Modifier.widthIn(max = 230.dp))
        if (disclosure) {
            Spacer(Modifier.width(8.dp))
            GlyphIcon(Glyph.Chevron, colors.secondaryLabel, 13.dp)
        }
    }
}

/** The text field being edited, in the screen's coordinates: a touch outside it closes the keyboard, as IQKeyboardManager does on iOS. */
object EditedField {
    var bounds: Rect? = null
}

fun Modifier.editedField(): Modifier = composed {
    val field = remember { object { var focused = false; var bounds: Rect? = null } }
    onGloballyPositioned {
        field.bounds = it.boundsInRoot()
        if (field.focused) EditedField.bounds = field.bounds
    }.onFocusChanged {
        field.focused = it.isFocused
        if (it.isFocused) EditedField.bounds = field.bounds else if (EditedField.bounds == field.bounds) EditedField.bounds = null
    }
}

/** A title with its text field on the right, right-aligned as in the iOS app. */
@Composable
fun TextFieldRow(
    title: String,
    value: String,
    placeholder: String,
    secure: Boolean = false,
    keyboardType: KeyboardType = KeyboardType.Ascii,
    enabled: Boolean = true,
    onDone: (() -> Unit)? = null,
    trailing: (@Composable () -> Unit)? = null,
    onValueChange: (String) -> Unit,
) {
    PressableRow(null) {
        Label(title, maxLines = 2, modifier = Modifier.widthIn(max = 200.dp))
        Spacer(Modifier.width(12.dp))
        InlineField(value, placeholder, secure, keyboardType, enabled, TextAlign.End, Modifier.weight(1f), title, onDone, onValueChange)
        if (trailing != null) {
            Spacer(Modifier.width(8.dp))
            trailing()
        }
    }
}

@Composable
fun InlineField(
    value: String,
    placeholder: String,
    secure: Boolean,
    keyboardType: KeyboardType,
    enabled: Boolean,
    alignment: TextAlign,
    modifier: Modifier,
    description: String,
    onDone: (() -> Unit)?,
    onValueChange: (String) -> Unit,
) {
    val colors = LocalIosColors.current
    val focus = LocalFocusManager.current
    BasicTextField(
        value = value,
        onValueChange = onValueChange,
        enabled = enabled,
        singleLine = true,
        modifier = modifier.editedField().semantics { contentDescription = description },
        textStyle = IosText.body.copy(color = colors.label, textAlign = alignment),
        cursorBrush = SolidColor(colors.blue),
        keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.None, autoCorrectEnabled = false, keyboardType = if (secure) KeyboardType.Password else keyboardType, imeAction = ImeAction.Done),
        keyboardActions = androidx.compose.foundation.text.KeyboardActions(onDone = {
            onDone?.invoke()
            focus.clearFocus()
        }),
        visualTransformation = if (secure) PasswordVisualTransformation() else VisualTransformation.None,
        decorationBox = { field ->
            Box(contentAlignment = if (alignment == TextAlign.End) Alignment.CenterEnd else Alignment.CenterStart) {
                if (value.isEmpty()) Label(placeholder, color = colors.tertiaryLabel, maxLines = 1, textAlign = alignment, modifier = Modifier.fillMaxWidth())
                field()
            }
        },
    )
}

/** The wide pill-shaped switch of current iOS. */
@Composable
fun IosSwitch(checked: Boolean, description: String, onCheckedChange: (Boolean) -> Unit) {
    val colors = LocalIosColors.current
    val track by animateColorAsState(if (checked) colors.green else colors.switchOff)
    val thumb by animateDpAsState(if (checked) 23.dp else 2.dp)
    Box(
        Modifier
            .size(64.dp, 28.dp)
            .clip(RoundedCornerShape(14.dp))
            .background(track)
            .clickable(role = Role.Switch, onClickLabel = description) { onCheckedChange(!checked) }
            .semantics { contentDescription = description },
    ) {
        Box(
            Modifier
                .offset(x = thumb, y = 2.dp)
                .size(39.dp, 24.dp)
                .shadow(1.dp, RoundedCornerShape(12.dp))
                .clip(RoundedCornerShape(12.dp))
                .background(Color.White),
        )
    }
}

@Composable
fun SwitchRow(title: String, checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    PressableRow(null) {
        Label(title, modifier = Modifier.weight(1f), maxLines = 2)
        Spacer(Modifier.width(12.dp))
        IosSwitch(checked, title, onCheckedChange)
    }
}

/** The capsule segmented control of current iOS. */
@Composable
fun SegmentedControl(items: List<String>, selected: Int, description: String, onSelect: (Int) -> Unit) {
    val colors = LocalIosColors.current
    Row(
        Modifier
            .height(36.dp)
            .clip(RoundedCornerShape(18.dp))
            .background(colors.fill)
            .padding(2.dp)
            .semantics { contentDescription = description },
    ) {
        items.forEachIndexed { index, item ->
            val isSelected = index == selected
            Box(
                Modifier
                    .fillMaxHeight()
                    .then(if (isSelected) Modifier.shadow(1.5.dp, RoundedCornerShape(16.dp)) else Modifier)
                    .clip(RoundedCornerShape(16.dp))
                    .background(if (isSelected) colors.segmentSelected else Color.Transparent)
                    .clickable(role = Role.RadioButton) { if (!isSelected) onSelect(index) }
                    .padding(horizontal = 12.dp),
                contentAlignment = Alignment.Center,
            ) {
                Label(item, IosText.subheadline.copy(fontSize = 14.sp, fontWeight = if (isSelected) FontWeight.SemiBold else FontWeight.Normal), maxLines = 1)
            }
        }
    }
}

@Composable
fun SegmentRow(title: String, items: List<String>, selected: Int, onSelect: (Int) -> Unit) {
    PressableRow(null) {
        Label(title, modifier = Modifier.weight(1f), maxLines = 2)
        Spacer(Modifier.width(8.dp))
        SegmentedControl(items, selected, title, onSelect)
    }
}

/** A choice row with a blue tick when it is the current one. */
@Composable
fun CheckRow(title: String, subtitle: String? = null, checked: Boolean, onClick: () -> Unit) {
    val colors = LocalIosColors.current
    PressableRow(onClick) {
        Column(Modifier.weight(1f)) {
            Label(title)
            if (subtitle != null) Label(subtitle, IosText.subheadline, colors.secondaryLabel)
        }
        if (checked) GlyphIcon(Glyph.Check, colors.blue, 18.dp)
    }
}

/** A short message in the middle of the screen, like the Toast pod of the iOS app. */
@Composable
fun ToastBubble(text: String, modifier: Modifier = Modifier) {
    Box(modifier.padding(horizontal = 40.dp).clip(RoundedCornerShape(10.dp)).background(Color(0xCC000000)).padding(horizontal = 14.dp, vertical = 10.dp)) {
        Label(text, IosText.subheadline, Color.White, textAlign = TextAlign.Center)
    }
}

/** An alert box with the shape of UIAlertController. */
@Composable
fun IosAlert(title: String, message: String?, onDismiss: () -> Unit) {
    val colors = LocalIosColors.current
    Dialog(onDismissRequest = onDismiss, properties = DialogProperties(usePlatformDefaultWidth = false, dismissOnClickOutside = false)) {
        Column(Modifier.width(280.dp).clip(RoundedCornerShape(14.dp)).background(colors.cell), horizontalAlignment = Alignment.CenterHorizontally) {
            Label(title, IosText.headline, textAlign = TextAlign.Center, modifier = Modifier.padding(start = 16.dp, end = 16.dp, top = 18.dp))
            if (!message.isNullOrEmpty()) Label(message, IosText.footnote, textAlign = TextAlign.Center, modifier = Modifier.padding(start = 16.dp, end = 16.dp, top = 6.dp))
            Spacer(Modifier.height(18.dp))
            Hairline()
            Box(Modifier.fillMaxWidth().height(46.dp).clickable(role = Role.Button, onClick = onDismiss), contentAlignment = Alignment.Center) {
                Label("OK", IosText.headline, colors.blue)
            }
        }
    }
}
