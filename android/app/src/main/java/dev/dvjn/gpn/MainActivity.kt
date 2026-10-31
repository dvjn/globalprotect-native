package dev.dvjn.gpn

import android.Manifest
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import dev.dvjn.gpn.mobile.Mobile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

class MainActivity : ComponentActivity() {
    private val store get() = Gpn.store

    /** message is the last error or notice, shown once as a snackbar. */
    private var message by mutableStateOf("")

    /** connectAfterLogin is set when connecting found no login, so the login's end connects. */
    private var connectAfterLogin = false

    /** portalSet ends onboarding; page is what shows after it. */
    private var portalSet by mutableStateOf(false)
    private var page by mutableStateOf(Page.HOME)

    /** hipProfile is the imported HIP profile, or "" to report this phone. */
    private var hipProfile by mutableStateOf("")

    /** hipPreview is the report to show, or "" when none is open. */
    private var hipPreview by mutableStateOf("")

    private val vpnPermission = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == RESULT_OK) startTunnel() else message = getString(R.string.vpn_permission_denied)
    }
    private val notificationPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) {}

    private val hipImport = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri ?: return@registerForActivityResult
        runCatching { contentResolver.openInputStream(uri)!!.use { String(it.readBytes()) } }
            .mapCatching { text -> text.also { JSONObject(it) } }
            .onSuccess {
                saveHIPProfile(it)
                message = getString(R.string.hip_imported)
            }
            .onFailure { message = it.message ?: it.toString() }
    }

    private val hipExport = registerForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri ->
        uri ?: return@registerForActivityResult
        runCatching {
            val exported = Mobile.exportHIPProfile(store.settingsJSON(needsLogin = false), BrowserLogin.LoginApp(this))
            contentResolver.openOutputStream(uri)!!.use { it.write(exported.toByteArray()) }
        }
            .onSuccess { message = getString(R.string.hip_exported) }
            .onFailure { message = it.message ?: it.toString() }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        hipProfile = store.hipProfile
        portalSet = store.portal.isNotBlank()
        setContent { Theme { Screen() } }
        handleCallback(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleCallback(intent)
    }

    /** handleCallback finishes a login when the browser opened a globalprotectcallback: link. */
    private fun handleCallback(intent: Intent?) {
        val uri = intent?.data?.takeIf { it.scheme == CALLBACK_SCHEME } ?: return
        setIntent(Intent(this, MainActivity::class.java))
        message = getString(R.string.logging_in)
        BrowserLogin.finish(uri.toString()) { error ->
            message = error ?: getString(R.string.logged_in, store.portal)
            if (error == null && connectAfterLogin) {
                connectAfterLogin = false
                connect()
            }
        }
    }

    private fun signOut() {
        disconnect()
        store.signOut()
        page = Page.HOME
        portalSet = false
    }

    private fun logIn() {
        message = getString(R.string.opening_login)
        BrowserLogin.start(this) { message = it }
    }

    private fun connect() {
        if (store.credential == null) {
            connectAfterLogin = true
            logIn()
            return
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        val consent = VpnService.prepare(this)
        if (consent != null) vpnPermission.launch(consent) else startTunnel()
    }

    private fun startTunnel() {
        startForegroundService(TunnelService.connectIntent(this))
    }

    private fun disconnect() {
        startService(TunnelService.disconnectIntent(this))
    }

    private fun saveHIPProfile(text: String) {
        hipProfile = text
        store.hipProfile = text
    }

    /** hipSummary says which machine the phone reports as. */
    private fun hipSummary(): String {
        if (hipProfile.isBlank()) return getString(R.string.hip_this_phone)
        val profile = runCatching { JSONObject(hipProfile) }.getOrNull() ?: return getString(R.string.hip_invalid)
        return getString(R.string.hip_imported_as, profile.optString("computer", "?"), profile.optString("os", "?"))
    }

    private fun previewHIP() {
        runCatching { Mobile.previewHIPReport(store.settingsJSON(needsLogin = false), BrowserLogin.LoginApp(this)) }
            .onSuccess { hipPreview = it }
            .onFailure { message = it.message ?: it.toString() }
    }

    /** Theme follows the wallpaper's colors where Android offers them. */
    @Composable
    private fun Theme(content: @Composable () -> Unit) {
        val dark = isSystemInDarkTheme()
        val context = LocalContext.current
        val colors = when {
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> if (dark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
            dark -> darkColorScheme()
            else -> lightColorScheme()
        }
        MaterialTheme(colorScheme = colors, content = content)
    }

    /** Page is a screen after onboarding; back goes to its parent. */
    private enum class Page(val title: Int, val parent: Page?) {
        HOME(R.string.app_name, null),
        SETTINGS(R.string.settings, HOME),
        ACCOUNT(R.string.page_account, SETTINGS),
        GATEWAY(R.string.page_gateway, SETTINGS),
        SPLIT(R.string.page_split, SETTINGS),
        HIP(R.string.page_hip, SETTINGS),
        ADVANCED(R.string.page_advanced, SETTINGS),
        LOG(R.string.page_log, SETTINGS),
    }

    @OptIn(ExperimentalMaterial3Api::class)
    @Composable
    private fun Screen() {
        val state by TunnelState.state.collectAsStateWithLifecycle()
        val snackbar = remember { SnackbarHostState() }
        LaunchedEffect(message) {
            if (message.isNotEmpty()) {
                snackbar.showSnackbar(message)
                message = ""
            }
        }
        page.parent?.let { parent -> BackHandler { page = parent } }

        Scaffold(
            topBar = {
                if (portalSet) {
                    TopAppBar(
                        title = { Text(getString(page.title)) },
                        navigationIcon = {
                            page.parent?.let { parent ->
                                IconButton({ page = parent }) {
                                    Icon(painterResource(R.drawable.ic_arrow_back), getString(R.string.back))
                                }
                            }
                        },
                        actions = {
                            if (page == Page.HOME) {
                                IconButton({ page = Page.SETTINGS }) {
                                    Icon(painterResource(R.drawable.ic_settings), getString(R.string.settings))
                                }
                            }
                        },
                    )
                }
            },
            snackbarHost = { SnackbarHost(snackbar) },
        ) { padding ->
            val modifier = Modifier.fillMaxSize().padding(padding)
            when {
                !portalSet -> Onboarding(modifier)
                page == Page.HOME -> Home(state, modifier)
                page == Page.SETTINGS -> SettingsList(modifier)
                else -> Column(modifier.verticalScroll(rememberScrollState()).padding(bottom = 24.dp)) {
                    when (page) {
                        Page.ACCOUNT -> AccountPage()
                        Page.GATEWAY -> GatewayPage()
                        Page.SPLIT -> SplitPage()
                        Page.HIP -> HIPPage()
                        Page.ADVANCED -> AdvancedPage()
                        else -> LogPage()
                    }
                }
            }
        }

        if (hipPreview.isNotEmpty()) {
            AlertDialog(
                onDismissRequest = { hipPreview = "" },
                confirmButton = { TextButton({ hipPreview = "" }) { Text(getString(R.string.close)) } },
                title = { Text(getString(R.string.hip_preview)) },
                text = {
                    SelectionContainer(Modifier.verticalScroll(rememberScrollState())) {
                        Text(hipPreview, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                    }
                },
            )
        }
    }

    /** Onboarding asks only for the portal, then logs in and connects. */
    @Composable
    private fun Onboarding(modifier: Modifier) {
        var portal by remember { mutableStateOf("") }
        val start = {
            store.portal = portal.trim()
            portalSet = true
            connect()
        }
        Column(
            modifier.imePadding().padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Icon(
                painterResource(R.drawable.ic_shield_check),
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(72.dp),
            )
            Text(getString(R.string.app_name), style = MaterialTheme.typography.headlineMedium)
            Text(
                getString(R.string.onboarding),
                style = MaterialTheme.typography.bodyLarge,
                textAlign = TextAlign.Center,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = portal,
                onValueChange = { portal = it },
                label = { Text(getString(R.string.portal)) },
                placeholder = { Text("vpn.example.com") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, imeAction = ImeAction.Go),
                keyboardActions = KeyboardActions(onGo = { if (portal.isNotBlank()) start() }),
                modifier = Modifier.fillMaxWidth(),
            )
            Button(start, enabled = portal.isNotBlank(), modifier = Modifier.fillMaxWidth().height(52.dp)) {
                Text(getString(R.string.continue_))
            }
        }
    }

    /** Home shows the tunnel and one button to connect or disconnect. */
    @Composable
    private fun Home(state: State, modifier: Modifier) {
        Column(modifier.padding(24.dp)) {
            Column(
                Modifier.fillMaxWidth().weight(1f),
                verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                StatusIcon(state)
                Text(title(state), style = MaterialTheme.typography.headlineMedium)
                Text(
                    detail(state),
                    style = MaterialTheme.typography.bodyMedium,
                    textAlign = TextAlign.Center,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (state.running) {
                OutlinedButton(::disconnect, Modifier.fillMaxWidth().height(56.dp)) { Text(getString(R.string.disconnect)) }
            } else {
                Button(::connect, Modifier.fillMaxWidth().height(56.dp)) { Text(getString(R.string.connect)) }
            }
        }
    }

    @Composable
    private fun StatusIcon(state: State) {
        val modifier = Modifier.size(120.dp)
        when (state.state) {
            State.CONNECTING, State.RECONNECTING -> CircularProgressIndicator(modifier.padding(12.dp), strokeWidth = 6.dp)
            State.CONNECTED -> Icon(painterResource(R.drawable.ic_shield_check), null, modifier, tint = CONNECTED)
            State.FAILED, State.NEEDS_LOGIN ->
                Icon(painterResource(R.drawable.ic_warning), null, modifier, tint = MaterialTheme.colorScheme.error)
            else -> Icon(painterResource(R.drawable.ic_shield_outline), null, modifier, tint = MaterialTheme.colorScheme.outline)
        }
    }

    private fun title(state: State) = getString(
        when (state.state) {
            State.CONNECTED -> R.string.state_connected
            State.CONNECTING -> R.string.state_connecting
            State.RECONNECTING -> R.string.state_reconnecting
            State.NEEDS_LOGIN -> R.string.state_needs_login
            State.FAILED -> R.string.state_failed
            else -> R.string.state_disconnected
        },
    )

    private fun detail(state: State) = when (state.state) {
        State.CONNECTED -> getString(R.string.connected_detail, state.gateway, state.clientIP, state.transport)
        State.RECONNECTING, State.FAILED, State.NEEDS_LOGIN -> state.error
        else -> store.portal
    }

    /** SettingsList is one row per page, each saying what it is set to. */
    @Composable
    private fun SettingsList(modifier: Modifier) {
        Column(modifier.verticalScroll(rememberScrollState())) {
            Row(Page.ACCOUNT, store.username?.let { getString(R.string.account_summary, it, store.portal) } ?: store.portal)
            Row(Page.GATEWAY, store.gateway.ifEmpty { getString(R.string.gateway_fastest) })
            Row(Page.SPLIT, splitSummary())
            Row(Page.HIP, hipSummary())
            Row(Page.ADVANCED, getString(if (store.sslOnly) R.string.ssl_only_on else R.string.ssl_only_off))
            Row(Page.LOG, getString(R.string.log_summary))
            Text(
                getString(R.string.settings_apply),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(16.dp),
            )
        }
    }

    @Composable
    private fun Row(target: Page, summary: String) {
        ListItem(
            headlineContent = { Text(getString(target.title)) },
            supportingContent = { Text(summary, maxLines = 1, overflow = TextOverflow.Ellipsis) },
            modifier = Modifier.clickable { page = target },
        )
    }

    private fun splitSummary(): String {
        if (!store.includeOnly) {
            val excluded = store.excludeDomains.lines().count(String::isNotBlank)
            return if (excluded == 0) getString(R.string.split_everything) else getString(R.string.split_everything_but, excluded)
        }
        val domains = store.includeDomains.lines().count(String::isNotBlank)
        val routes = store.includeRoutes.lines().count(String::isNotBlank)
        return getString(R.string.split_only_summary, domains, routes)
    }

    @Composable
    private fun AccountPage() {
        ListItem(headlineContent = { Text(getString(R.string.portal)) }, supportingContent = { Text(store.portal) })
        ListItem(
            headlineContent = { Text(getString(R.string.account_user)) },
            supportingContent = { Text(store.username ?: getString(R.string.account_logged_out)) },
        )
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            FilledTonalButton(::logIn, Modifier.fillMaxWidth()) { Text(getString(R.string.log_in_again)) }
            OutlinedButton(::signOut, Modifier.fillMaxWidth()) { Text(getString(R.string.sign_out)) }
            Hint(R.string.sign_out_detail)
        }
    }

    /** GatewayPage offers the fastest gateway and each one the portal lists. */
    @Composable
    private fun GatewayPage() {
        var chosen by remember { mutableStateOf(store.gateway) }
        var gateways by remember { mutableStateOf<List<Pair<String, String>>?>(null) }
        var error by remember { mutableStateOf("") }
        LaunchedEffect(Unit) {
            val settings = runCatching { store.settingsJSON() }.getOrNull()
            if (settings == null) {
                error = getString(R.string.gateway_log_in)
                return@LaunchedEffect
            }
            withContext(Dispatchers.IO) { runCatching { Mobile.gateways(settings, BrowserLogin.LoginApp(this@MainActivity)) } }
                .onSuccess { listed ->
                    val array = JSONArray(listed)
                    gateways = (0 until array.length()).map { array.getJSONObject(it).let { g -> g.getString("name") to g.getString("address") } }
                }
                .onFailure { error = it.message ?: it.toString() }
        }
        val choose = { name: String ->
            chosen = name
            store.gateway = name
        }

        Choice(getString(R.string.gateway_fastest), getString(R.string.gateway_fastest_detail), chosen.isEmpty()) { choose("") }
        when {
            gateways != null -> gateways!!.forEach { (name, address) -> Choice(name, address, chosen == name) { choose(name) } }
            error.isNotEmpty() -> Text(error, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(16.dp))
            else -> CircularProgressIndicator(Modifier.padding(16.dp).size(24.dp), strokeWidth = 2.dp)
        }
        // A gateway saved earlier that the portal no longer lists stays selectable.
        if (chosen.isNotEmpty() && gateways != null && gateways!!.none { it.first == chosen }) {
            Choice(chosen, getString(R.string.gateway_unlisted), true) {}
        }
    }

    /** SplitPage picks what goes through the VPN, and shows only that choice's lists. */
    @Composable
    private fun SplitPage() {
        var includeOnly by remember { mutableStateOf(store.includeOnly) }
        val choose = { only: Boolean ->
            includeOnly = only
            store.includeOnly = only
        }
        Choice(getString(R.string.split_everything), getString(R.string.split_everything_detail), !includeOnly) { choose(false) }
        Choice(getString(R.string.split_only), getString(R.string.split_only_detail), includeOnly) { choose(true) }
        HorizontalDivider(Modifier.padding(vertical = 8.dp))
        if (includeOnly) {
            Field(R.string.include_domains, store.includeDomains, lines = 3, hint = R.string.include_domains_hint) { store.includeDomains = it }
            Field(R.string.include_routes, store.includeRoutes, lines = 3, hint = R.string.include_routes_hint) { store.includeRoutes = it }
        } else {
            Field(R.string.exclude_domains, store.excludeDomains, lines = 3, hint = R.string.exclude_domains_hint) { store.excludeDomains = it }
        }
    }

    @Composable
    private fun HIPPage() {
        Toggle(R.string.send_hip, R.string.send_hip_detail, store.sendHIP) { store.sendHIP = it }
        HorizontalDivider(Modifier.padding(vertical = 8.dp))
        ListItem(headlineContent = { Text(getString(R.string.hip_profile)) }, supportingContent = { Text(hipSummary()) })
        Column(Modifier.padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            FilledTonalButton({ hipImport.launch(arrayOf("application/json", "text/plain")) }, Modifier.fillMaxWidth()) {
                Text(getString(R.string.hip_import))
            }
            OutlinedButton({ hipExport.launch("hip-profile.json") }, Modifier.fillMaxWidth()) { Text(getString(R.string.hip_export)) }
            OutlinedButton(::previewHIP, Modifier.fillMaxWidth()) { Text(getString(R.string.hip_preview)) }
            if (hipProfile.isNotBlank()) {
                TextButton({ saveHIPProfile("") }, Modifier.fillMaxWidth()) { Text(getString(R.string.hip_clear)) }
            }
            Hint(R.string.hip_detail)
        }
    }

    @Composable
    private fun AdvancedPage() {
        Toggle(R.string.ssl_only, R.string.ssl_only_detail, store.sslOnly) { store.sslOnly = it }
    }

    @Composable
    private fun LogPage() {
        val log by TunnelState.log.collectAsStateWithLifecycle()
        SelectionContainer(Modifier.padding(16.dp)) {
            Text(
                log.joinToString("\n").ifEmpty { getString(R.string.log_empty) },
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }

    @Composable
    private fun Choice(title: String, detail: String, selected: Boolean, choose: () -> Unit) {
        ListItem(
            headlineContent = { Text(title) },
            supportingContent = { Text(detail) },
            leadingContent = { RadioButton(selected, onClick = choose) },
            modifier = Modifier.clickable(onClick = choose),
        )
    }

    @Composable
    private fun Hint(text: Int) {
        Text(getString(text), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }

    @Composable
    private fun Field(label: Int, initial: String, lines: Int = 1, hint: Int? = null, save: (String) -> Unit) {
        var value by remember { mutableStateOf(initial) }
        OutlinedTextField(
            value = value,
            onValueChange = {
                value = it
                save(it)
            },
            label = { Text(getString(label)) },
            supportingText = hint?.let { { Text(getString(it)) } },
            singleLine = lines == 1,
            minLines = lines,
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp),
        )
    }

    @Composable
    private fun Toggle(label: Int, detail: Int, initial: Boolean, save: (Boolean) -> Unit) {
        var checked by remember { mutableStateOf(initial) }
        val toggle = { value: Boolean ->
            checked = value
            save(value)
        }
        ListItem(
            headlineContent = { Text(getString(label)) },
            supportingContent = { Text(getString(detail)) },
            trailingContent = { Switch(checked, onCheckedChange = toggle) },
            modifier = Modifier.clickable { toggle(!checked) },
        )
    }

    private companion object {
        const val CALLBACK_SCHEME = "globalprotectcallback"
        val CONNECTED = Color(0xFF3CC86E)
    }
}
