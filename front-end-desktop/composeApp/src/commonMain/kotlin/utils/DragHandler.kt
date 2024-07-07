package utils

import androidx.compose.ui.unit.IntOffset
import java.awt.MouseInfo
import java.awt.Point
import java.awt.Window
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.awt.event.MouseMotionAdapter

/**
 * This class handles the dragging of a window.
 *
 * @param window The window to be dragged.
 */
class DragHandler(private val window: Window) {

    // The location of the window.
    private var location = window.location.toComposeOffset()

    // The point where the dragging starts.
    private var pointStart = MouseInfo.getPointerInfo().location.toComposeOffset()

    /**
     * This listener drags the window.
     */
    private val dragListener = object : MouseMotionAdapter() {
        override fun mouseDragged(event: MouseEvent) = drag()
    }

    /**
     * This listener removes the drag listener when the mouse is released.
     */
    private val removeListener = object : MouseAdapter() {
        override fun mouseReleased(event: MouseEvent) {
            window.removeMouseMotionListener(dragListener)
            window.removeMouseListener(this)
        }
    }

    /**
     * This function registers the window for dragging.
     */
    fun register() {
        location = window.location.toComposeOffset()
        pointStart = MouseInfo.getPointerInfo().location.toComposeOffset()
        window.addMouseListener(removeListener)
        window.addMouseMotionListener(dragListener)
    }

    /**
     * This function drags the window.
     */
    private fun drag() {
        val point = MouseInfo.getPointerInfo().location.toComposeOffset()
        val location = location + (point - pointStart)
        window.setLocation(location.x, location.y)
    }

    /**
     * This function converts a point to a Compose offset.
     *
     * @return The Compose offset.
     */
    private fun Point.toComposeOffset() = IntOffset(x, y)
}