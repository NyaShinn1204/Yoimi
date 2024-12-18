import customtkinter
import tkinter as tk
from tkinter import ttk
import sys
import time

class CTkDropdownTest(customtkinter.CTkToplevel):
    
    def __init__(self, attach, x=None, y=None, button_color=None, height: int = 200, width: int = None,
                 fg_color=None, button_height: int = 20, justify="center", scrollbar_button_color=None,
                 scrollbar=True, scrollbar_button_hover_color=None, frame_border_width=2, values=[],
                 tree_colum=[], command=None, image_values=[], alpha: float = 0.97, frame_corner_radius=20, 
                 double_click=False, resize=True, frame_border_color=None, text_color=None, autocomplete=False, 
                 hover_color=None, tree_fg_color=None, tree_bg_color=None, **button_kwargs):
        
        super().__init__(master=attach.winfo_toplevel(), takefocus=1)
        
        self.focus()
        self.lift()
        self.alpha = alpha
        self.attach = attach
        self.corner = frame_corner_radius
        self.padding = 0
        self.focus_something = False
        self.disable = True
        self.update()
        
        self.tree_fg_color = tree_fg_color if tree_fg_color else "SystemWindowText"
        self.tree_bg_color = tree_bg_color if tree_bg_color else "SystemWindow"
        
        if sys.platform.startswith("win"):
            self.after(100, lambda: self.overrideredirect(True))
            self.transparent_color = self._apply_appearance_mode(self._fg_color)
            self.attributes("-transparentcolor", self.transparent_color)
        elif sys.platform.startswith("darwin"):
            self.overrideredirect(True)
            self.transparent_color = 'systemTransparent'
            self.attributes("-transparent", True)
            self.focus_something = True
        else:
            self.overrideredirect(True)
            self.transparent_color = '#000001'
            self.corner = 0
            self.padding = 18
            self.withdraw()

        self.hide = True
        self.attach.bind('<Configure>', lambda e: self._withdraw() if not self.disable else None, add="+")
        self.attach.winfo_toplevel().bind('<Configure>', lambda e: self._withdraw() if not self.disable else None, add="+")
        self.bind("<Escape>", lambda e: self._withdraw() if not self.disable else None, add="+")
        
        self.attributes('-alpha', 0)
        self.disable = False
        self.fg_color = customtkinter.ThemeManager.theme["CTkFrame"]["fg_color"] if fg_color is None else fg_color
        self.scroll_button_color = customtkinter.ThemeManager.theme["CTkScrollbar"]["button_color"] if scrollbar_button_color is None else scrollbar_button_color
        self.scroll_hover_color = customtkinter.ThemeManager.theme["CTkScrollbar"]["button_hover_color"] if scrollbar_button_hover_color is None else scrollbar_button_hover_color
        self.frame_border_color = customtkinter.ThemeManager.theme["CTkFrame"]["border_color"] if frame_border_color is None else frame_border_color
        self.button_color = customtkinter.ThemeManager.theme["CTkFrame"]["top_fg_color"] if button_color is None else button_color
        self.text_color = customtkinter.ThemeManager.theme["CTkLabel"]["text_color"] if text_color is None else text_color
        self.hover_color = customtkinter.ThemeManager.theme["CTkButton"]["hover_color"] if hover_color is None else hover_color
        
        if scrollbar is False:
            self.scroll_button_color = self.fg_color
            self.scroll_hover_color = self.fg_color
            
        # Initialize Treeview widget
        self.tree_frame = customtkinter.CTkScrollableFrame(self, bg_color=self.transparent_color, fg_color=self.fg_color,
                                        scrollbar_button_hover_color=self.scroll_hover_color,
                                        corner_radius=self.corner, border_width=frame_border_width,
                                        scrollbar_button_color=self.scroll_button_color,
                                        border_color=self.frame_border_color)
        self.tree_frame._scrollbar.grid_configure(padx=3)
        self.tree_frame.pack(expand=True, fill="both")
        
        self.tree = ttk.Treeview(self.tree_frame, columns=tree_colum, show='headings',
                                 
                                 selectmode='browse', 
                                 style="Custom.Treeview")
        for col in tree_colum:
            self.tree.heading(col, text=col)
        self.tree.pack(side="left", fill="both", expand=True)
        
        # Apply the colors to Treeview
        style = ttk.Style()
        style.theme_use("default")
        print(self.tree_bg_color)
        style.configure("Custom.Treeview",
                        background=self.tree_bg_color,
                        foreground=self.tree_fg_color,
                        fieldbackground=self.tree_bg_color)
        style.configure("Custom.Treeview.Heading",
                        background=self.tree_bg_color,
                        foreground=self.tree_fg_color)
        style.map('Custom.Treeview',
                  background=[('selected', '#274f62')],
        )

        # Scrollbar setup
        self.scrollbar = tk.Scrollbar(self.tree_frame, orient="vertical", command=self.tree.yview)
        self.scrollbar.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=self.scrollbar.set)

        self.dummy_entry = customtkinter.CTkEntry(self.tree_frame, fg_color="transparent", border_width=0, height=1, width=1)
        self.no_match = customtkinter.CTkLabel(self.tree_frame, text="No Match")
        self.height = height
        self.height_new = height
        self.width = width
        self.command = command
        self.fade = False
        self.resize = resize
        self.autocomplete = autocomplete
        self.var_update = customtkinter.StringVar()
        self.appear = False
        
        if justify.lower()=="left":
            self.justify = "w"
        elif justify.lower()=="right":
            self.justify = "e"
        else:
            self.justify = "c"
            
        self.button_height = button_height
        self.values = values
        self.button_num = len(self.values)
        self.image_values = None if len(image_values)!=len(self.values) else image_values
        
        self.resizable(width=False, height=False)
        self.transient(self.master)
        self._init_tree(**button_kwargs)

        # Add binding for different ctk widgets
        self.attach.bind('<Button-1>', lambda e: self._toggle_visibility(), add="+")
        
        if isinstance(self.attach, customtkinter.CTkComboBox):
            self.attach._canvas.tag_bind("right_parts", "<Button-1>", lambda e: self._toggle_visibility())
            self.attach._canvas.tag_bind("dropdown_arrow", "<Button-1>", lambda e: self._toggle_visibility())
            if self.command is None:
                self.command = self.attach.set
              
        if isinstance(self.attach, customtkinter.CTkOptionMenu):
            self.attach._canvas.bind("<Button-1>", lambda e: self._toggle_visibility())
            self.attach._text_label.bind("<Button-1>", lambda e: self._toggle_visibility())
            if self.command is None:
                self.command = self.attach.set
                
        self.bind("<Destroy>", lambda _: self._destroy(), add="+")
        
        self.update_idletasks()
        self.x = x
        self.y = y

        if self.autocomplete:
            self.bind_autocomplete()
            
        self.withdraw()

        self.attributes("-alpha", self.alpha)

        # Bind row selection event
        self.tree.bind("<ButtonRelease-1>", self.on_row_select)

    def _destroy(self):
        self.after(500, self.destroy_popup)
        
    def _withdraw(self):
        if not self.winfo_exists():
            return
        if self.winfo_viewable() and self.hide:
            self.withdraw()
        
        self.event_generate("<<Closed>>")
        self.hide = True

    def _update(self, a, b, c):
        self.live_update(self.attach._entry.get())
        
    def bind_autocomplete(self):
        def appear(x):
            self.appear = True
            
        if isinstance(self.attach, customtkinter.CTkComboBox):
            self.attach._entry.configure(textvariable=self.var_update)
            self.attach._entry.bind("<Key>", appear)
            self.attach.set(self.values[0])
            self.var_update.trace_add('write', self._update)
            
        if isinstance(self.attach, customtkinter.CTkEntry):
            self.attach.configure(textvariable=self.var_update)
            self.attach.bind("<Key>", appear)
            self.var_update.trace_add('write', self._update)
        
    def fade_out(self):
        for i in range(100,0,-10):
            if not self.winfo_exists():
                break
            self.attributes("-alpha", i/100)
            self.update()
            time.sleep(1/100)
            
    def fade_in(self):
        for i in range(0,100,10):
            if not self.winfo_exists():
                break
            self.attributes("-alpha", i/100)
            self.update()
            time.sleep(1/100)
            
    def _init_tree(self, **button_kwargs):
        for row in self.values:
            self.tree.insert('', 'end', values=row)
 
        self.hide = False
            
    def destroy_popup(self):
        self.destroy()
        self.disable = True

    def place_dropdown(self):
        self.x_pos = self.attach.winfo_rootx() if self.x is None else self.x + self.attach.winfo_rootx()
        self.y_pos = self.attach.winfo_rooty() + self.attach.winfo_reqheight() + 2 if self.y is None else self.y + self.attach.winfo_rooty()
        
        self.geometry(f"{self.width}x{self.height}+{self.x_pos}+{self.y_pos}")
        self.deiconify()
        self.update()
        if not self.appear:
            self.fade_in()
        self.after(50, self.focus_set)
        self.after(150, self.focus_set)

    def on_row_select(self, event):
        selected_items = self.tree.selection()
        if selected_items:
            item = selected_items[0]
            values = self.tree.item(item, 'values')
            if self.command:
                self.command({
                    "columns": self.tree["columns"],
                    "values": values
                })
            self._withdraw()  # Close the frame after selection

    def configure(self, values=None, **kwargs):
        if values is not None:
            self.values = values
            self._update_tree()  # Treeviewの内容を更新

    def _update_tree(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        for row in self.values:
            self.tree.insert('', 'end', values=row)

    def _toggle_visibility(self):
        if self.winfo_ismapped():
            self._withdraw()
        else:
            self.place_dropdown()
