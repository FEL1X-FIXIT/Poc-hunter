"""
PoC Hunter Mobile — Kivy-based Android app for CVE PoC searching
Compiles to APK with buildozer for Termux/Android deployment
"""

import kivy
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.textinput import TextInput
from kivy.uix.spinner import Spinner
from kivy.uix.checkbox import CheckBox
from kivy.uix.recycleview import RecycleView
from kivy.uix.recycleview.views import RecycleDataViewBehavior
from kivy.uix.boxlayout import BoxLayout as RecycleBoxLayout
from kivy.uix.popup import Popup
from kivy.uix.progressbar import ProgressBar
from kivy.garden.navigationdrawer import NavigationDrawer
from kivy.core.window import Window
from kivy.uix.stacklayout import StackLayout
from kivy.uix.relativelayout import RelativeLayout
from kivy.threading import Thread
from kivy.clock import mainthread, Clock
from kivy.uix.scrollview import ScrollView as KvScrollView

import platform
import webbrowser
import urllib.parse

# Import the pure search logic
from poc_hunter_logic import (
    PoCSearcher, SOURCES, SearchResult, YEARS
)

# Set window size for preview/testing (mobile ignores this)
Window.size = (450, 800)


class ResultItem(RecycleDataViewBehavior, RecycleBoxLayout):
    """Individual result item in the RecycleView"""
    index = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.size_hint_y = None
        self.height = 100
        self.orientation = 'vertical'
        self.padding = 5
        self.spacing = 2

    def refresh_view_data(self, index, data):
        """Called by RecycleView to update this item with data"""
        self.index = index
        self.data = data
        self.clear_widgets()

        if not data:
            return

        cve = data.get('cve_id', '')
        poc = data.get('poc_name', '')
        source = data.get('source', '')
        kev_marker = " [KEV]" if data.get('kev', False) else ""

        # CVE ID + source + KEV marker
        title = Label(
            text=f"[b]{cve}[/b] ({source}){kev_marker}",
            markup=True,
            size_hint_y=0.3,
            color=(1, 1, 1, 1)
        )
        self.add_widget(title)

        # PoC name/repo
        poc_label = Label(
            text=poc[:50] + "..." if len(poc) > 50 else poc,
            size_hint_y=0.2,
            color=(0.7, 0.9, 1, 1)
        )
        self.add_widget(poc_label)

        # Description summary
        summary = data.get('summary', '(no description)')
        desc_label = Label(
            text=summary[:60] + "..." if len(summary) > 60 else summary,
            size_hint_y=0.3,
            color=(0.8, 0.8, 0.8, 1)
        )
        self.add_widget(desc_label)


class PoCHunterApp(App):
    def build(self):
        self.title = "PoC Hunter"
        self.searcher = None
        self.search_thread = None

        # Main container
        main = BoxLayout(orientation='vertical', spacing=10, padding=10)

        # Top: Input controls
        controls = BoxLayout(orientation='vertical', spacing=8, size_hint_y=0.3)

        # Year + Keyword row
        input_row = BoxLayout(size_hint_y=None, height=40, spacing=5)

        # Year spinner
        self.year_spinner = Spinner(
            text=str(2024),
            values=YEARS,
            size_hint_x=0.25
        )
        input_row.add_widget(Label(text="Year:", size_hint_x=0.1))
        input_row.add_widget(self.year_spinner)

        # Keyword input
        self.keyword_input = TextInput(
            hint_text="Keyword (optional)",
            multiline=False,
            size_hint_x=0.65
        )
        input_row.add_widget(self.keyword_input)

        controls.add_widget(input_row)

        # Match target selector
        match_row = BoxLayout(size_hint_y=None, height=40, spacing=5)
        self.match_target = Spinner(
            text="All fields",
            values=["All fields", "CVE ID", "Description only", "Filename only"],
            size_hint_x=0.5
        )
        match_row.add_widget(Label(text="Match:", size_hint_x=0.2))
        match_row.add_widget(self.match_target)
        match_row.add_widget(Label(size_hint_x=0.3))

        controls.add_widget(match_row)

        # Source checkboxes (wrapped in scrollable container)
        src_scroll = ScrollView(size_hint_y=0.5)
        src_grid = GridLayout(cols=2, spacing=5, size_hint_y=None, padding=5)
        src_grid.bind(minimum_height=src_grid.setter('height'))

        self.source_checks = {}
        for key, info in SOURCES.items():
            src_box = BoxLayout(size_hint_y=None, height=30, spacing=5)
            chk = CheckBox(active=True, size_hint_x=0.2)
            lbl = Label(
                text=info["label"],
                size_hint_x=0.8,
                color=(1, 1, 1, 1)
            )
            src_box.add_widget(chk)
            src_box.add_widget(lbl)
            src_grid.add_widget(src_box)
            self.source_checks[key] = chk

        src_scroll.add_widget(src_grid)
        controls.add_widget(src_scroll)

        main.add_widget(controls)

        # Search button + status
        button_row = BoxLayout(size_hint_y=0.08, spacing=5)
        self.search_btn = Button(
            text="Search",
            background_color=(0.2, 0.6, 1, 1),
            size_hint_x=0.7
        )
        self.search_btn.bind(on_press=self.on_search)
        button_row.add_widget(self.search_btn)

        self.status_label = Label(
            text="Ready",
            size_hint_x=0.3,
            color=(0.8, 0.8, 0.8, 1)
        )
        button_row.add_widget(self.status_label)

        main.add_widget(button_row)

        # Progress bar
        self.progress = ProgressBar(
            value=0,
            size_hint_y=0.03,
            max=100
        )
        main.add_widget(self.progress)

        # Results RecycleView
        self.results_rv = RecycleView(
            data=[],
            size_hint_y=0.54,
            viewclass='ResultItem'
        )
        self.results_rv.bind(on_touch_down=self.on_result_touch)
        main.add_widget(self.results_rv)

        # Bottom: Result detail popup button
        detail_btn = Button(
            text="View Detail / Open URL",
            size_hint_y=0.05,
            background_color=(0.4, 0.7, 0.4, 1)
        )
        detail_btn.bind(on_press=self.show_detail_popup)
        main.add_widget(detail_btn)

        self.selected_result = None
        return main

    def on_search(self, instance):
        """Initiate search"""
        if self.search_thread and self.search_thread.is_alive():
            self.status_label.text = "Already searching..."
            return

        year = self.year_spinner.text
        keyword = self.keyword_input.text.strip()
        match_target = self.match_target.text

        # Collect active sources
        active_sources = [k for k, chk in self.source_checks.items() if chk.active]

        if not active_sources:
            self.status_label.text = "Select sources!"
            return

        self.progress.value = 0
        self.status_label.text = "Searching..."
        self.search_btn.disabled = True
        self.results_rv.data = []

        # Run search in background thread
        self.search_thread = Thread(
            target=self._do_search,
            args=(year, keyword, match_target, active_sources)
        )
        self.search_thread.daemon = True
        self.search_thread.start()

    def _do_search(self, year, keyword, match_target, active_sources):
        """Background search worker"""
        try:
            self.searcher = PoCSearcher(callback=self._search_callback)
            results = []

            for i, src_key in enumerate(active_sources):
                try:
                    src_results = self.searcher.search_source(
                        src_key, year, keyword, match_target
                    )
                    for r in src_results:
                        self.searcher.add_result(r)
                    results.extend(src_results)
                except Exception as e:
                    self._update_status(f"Error in {src_key}: {str(e)[:40]}")

                # Update progress
                progress = int((i + 1) / len(active_sources) * 100)
                self._update_progress(progress)

            # Convert to dict for RecycleView
            self._update_results([
                {
                    'cve_id': r.cve_id,
                    'source': r.source,
                    'poc_name': r.poc_name,
                    'html_url': r.html_url,
                    'description': r.description,
                    'nvd_description': r.nvd_description,
                    'summary': r.summary,
                    'kev': r.kev,
                }
                for r in self.searcher.results
            ])

            self._update_status(f"Found {len(self.searcher.results)} results")

        except Exception as e:
            self._update_status(f"Error: {str(e)[:60]}")

        finally:
            self._search_done()

    def _search_callback(self, event_type, data):
        """Callback from searcher for progress updates"""
        if event_type == "error":
            self._update_status(f"Error: {str(data)[:50]}")
        elif event_type == "result_added":
            pass  # Update will happen when search completes

    @mainthread
    def _update_status(self, text):
        """Update status label safely from thread"""
        self.status_label.text = text[:30]

    @mainthread
    def _update_progress(self, value):
        """Update progress bar safely from thread"""
        self.progress.value = value

    @mainthread
    def _update_results(self, results_data):
        """Update results RecycleView safely from thread"""
        self.results_rv.data = results_data

    @mainthread
    def _search_done(self):
        """Re-enable search button safely from thread"""
        self.search_btn.disabled = False

    def on_result_touch(self, instance, touch):
        """Select result on tap"""
        if instance.collide_point(*touch.pos):
            # Simple selection: track which result was tapped
            # In a full implementation, could use touch.y to determine which item
            if self.results_rv.data:
                # For now, select first result for demo
                # In production, use touch position to find exact item
                self.selected_result = self.results_rv.data[0] if self.results_rv.data else None
                return True
        return False

    def show_detail_popup(self, instance):
        """Show detail popup and open URL button"""
        if not self.results_rv.data:
            return

        # Use first result for now (would improve with actual selection tracking)
        result = self.results_rv.data[0]

        # Create popup content
        content = BoxLayout(orientation='vertical', spacing=10, padding=10)

        # CVE info
        cve_text = f"[b]CVE ID:[/b] {result['cve_id']}"
        if result['kev']:
            cve_text += " [KEV]"
        content.add_widget(Label(
            text=cve_text,
            markup=True,
            size_hint_y=0.15
        ))

        # Source
        content.add_widget(Label(
            text=f"[b]Source:[/b] {result['source']}",
            markup=True,
            size_hint_y=0.1
        ))

        # PoC name
        content.add_widget(Label(
            text=f"[b]PoC:[/b] {result['poc_name']}",
            markup=True,
            size_hint_y=0.15
        ))

        # Descriptions
        desc_scroll = ScrollView(size_hint_y=0.35)
        desc_box = BoxLayout(orientation='vertical', size_hint_y=None)
        desc_box.bind(minimum_height=desc_box.setter('height'))

        if result['nvd_description']:
            desc_box.add_widget(Label(
                text=f"[b]NVD:[/b] {result['nvd_description']}",
                markup=True,
                size_hint_y=None,
                height=80,
                text_size=(400, None)
            ))

        if result['description']:
            desc_box.add_widget(Label(
                text=f"[b]PoC Desc:[/b] {result['description']}",
                markup=True,
                size_hint_y=None,
                height=80,
                text_size=(400, None)
            ))

        desc_scroll.add_widget(desc_box)
        content.add_widget(desc_scroll)

        # URL
        if result['html_url']:
            url_label = Label(
                text=f"[b]URL:[/b] {result['html_url'][:60]}...",
                markup=True,
                size_hint_y=0.1
            )
            content.add_widget(url_label)

        # Buttons
        btn_box = BoxLayout(size_hint_y=0.15, spacing=5)

        if result['html_url']:
            open_btn = Button(
                text="Open URL",
                background_color=(0.2, 0.8, 0.2, 1)
            )
            url = result['html_url']
            open_btn.bind(on_press=lambda x: self._open_url(url))
            btn_box.add_widget(open_btn)

        close_btn = Button(
            text="Close",
            background_color=(0.8, 0.2, 0.2, 1)
        )
        btn_box.add_widget(close_btn)

        content.add_widget(btn_box)

        # Create and show popup
        popup = Popup(
            title=f"Details: {result['cve_id']}",
            content=content,
            size_hint=(0.9, 0.8)
        )
        close_btn.bind(on_press=popup.dismiss)
        popup.open()

    def _open_url(self, url):
        """Open URL in browser"""
        try:
            # Try Kivy's default browser opener
            import platform as plat
            if plat.system() == "Android":
                # On Android, use intent
                from jnius import autoclass
                PythonActivity = autoclass('org.kivy.android.PythonActivity')
                Intent = autoclass('android.content.Intent')
                Uri = autoclass('android.net.Uri')

                activity = PythonActivity.mPythonActivity
                intent = Intent()
                intent.setAction(Intent.ACTION_VIEW)
                intent.setData(Uri.parse(url))
                activity.startActivity(intent)
            else:
                # Fallback for other platforms
                webbrowser.open(url)
        except Exception as e:
            print(f"Error opening URL: {e}")


if __name__ == '__main__':
    PoCHunterApp().run()
