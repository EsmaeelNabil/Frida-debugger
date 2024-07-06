/**
 * Enum class representing different pages in the application with their respective indices.
 *
 * @property index The index associated with the page.
 * @constructor Creates a page with the given index.
 *
 * Example usage:
 * ```kotlin
 * val currentPage = Pages.APPS
 * val pageIndex = currentPage.index
 * ```
 */
enum class Pages(val index: Int) {
    APPS(0),
    SCRIPT(1)
}
