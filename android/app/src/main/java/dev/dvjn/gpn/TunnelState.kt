package dev.dvjn.gpn

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

/** State is the tunnel's state as the Go core reports it; state is one of the control.State values. */
data class State(
    val state: String = DISCONNECTED,
    val gateway: String = "",
    val clientIP: String = "",
    val transport: String = "",
    val error: String = "",
) {
    val running get() = state in setOf(CONNECTING, CONNECTED, RECONNECTING)

    val summary
        get() = when (state) {
            CONNECTED -> "Connected to $gateway over $transport as $clientIP"
            CONNECTING -> "Connecting…"
            RECONNECTING -> "Reconnecting: $error"
            NEEDS_LOGIN -> "Needs a login"
            FAILED -> "Failed: $error"
            else -> "Disconnected"
        }

    companion object {
        const val CONNECTING = "connecting"
        const val CONNECTED = "connected"
        const val RECONNECTING = "reconnecting"
        const val NEEDS_LOGIN = "needs-login"
        const val FAILED = "failed"
        const val DISCONNECTED = "disconnected"
    }
}

/** TunnelState is what the UI shows: the tunnel's state and the core's recent log. */
object TunnelState {
    private const val LOG_LINES = 200

    private val mutableState = MutableStateFlow(State())
    val state: StateFlow<State> = mutableState.asStateFlow()

    private val mutableLog = MutableStateFlow(emptyList<String>())
    val log: StateFlow<List<String>> = mutableLog.asStateFlow()

    fun set(state: State) {
        mutableState.value = state
    }

    fun log(line: String) {
        mutableLog.update { (it + line).takeLast(LOG_LINES) }
    }
}
