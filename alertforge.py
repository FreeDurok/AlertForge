#!/usr/bin/env python3
"""
AlertForge - Security Bulletin Infographic Generator
Genera infografiche professionali per bollettini di sicurezza.

Autore: @Durok
Versione: 1.0
"""

from PIL import Image, ImageDraw, ImageFont
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum
from datetime import datetime
import textwrap
import os
import json
import argparse
import sys
import glob as file_glob


class Severity(Enum):
    """Livelli di severity con colori associati."""
    CRITICAL = ("critical", "#DC2626")
    HIGH = ("high", "#EA580C")
    MEDIUM = ("medium", "#CA8A04")
    LOW = ("low", "#16A34A")
    INFO = ("info", "#2563EB")


class Category(Enum):
    """Categorie di bollettini."""
    AGGIORNAMENTI = ("aggiornamenti", "Aggiornamenti")
    VULNERABILITA = ("vulnerabilita", "Vulnerabilità")
    PATCH = ("patch", "Patch")
    ADVISORY = ("advisory", "Advisory")
    INCIDENT = ("incident", "Incident")
    EXPLOIT = ("exploit", "Exploit")


@dataclass
class BulletinItem:
    """Rappresenta un singolo elemento del bollettino."""
    category: Category
    severity: Severity
    product: str
    description: str
    tags: list[str] = field(default_factory=list)
    cve_id: Optional[str] = None
    version: Optional[str] = None
    image_path: Optional[str] = None  # Immagine da mostrare sotto la card


@dataclass
class BulletinConfig:
    """Configurazione per la generazione dell'infografica."""
    width: int = 2400           # Raddoppiato per alta risoluzione
    height: int = 1600          # Raddoppiato per alta risoluzione
    background_color: str = "#0F172A"  # Slate 900
    accent_color: str = "#3B82F6"      # Blue 500
    text_color: str = "#F8FAFC"        # Slate 50
    secondary_text: str = "#94A3B8"    # Slate 400
    card_bg: str = "#1E293B"           # Slate 800
    logo_path: Optional[str] = None
    logo_bg_replace: bool = False      # Se True, sostituisce lo sfondo del logo
    logo_bg_color: Optional[str] = None  # Colore da sostituire (None = auto-detect nero/bianco)
    organization: str = "Security Operations Center"
    title: str = "Bollettino di Sicurezza"
    date: Optional[str] = None
    footer_text: str = "Confidential - Internal Use Only"


# Costanti di layout
MARGIN = 80
HEADER_LINE_HEIGHT = 12
HEADER_Y_START = 60
HEADER_END_Y = 300
FOOTER_HEIGHT = 120
CARD_RADIUS = 24
LOGO_MAX_SIZE = 160


# =============================================================================
# FUNZIONI DI UTILITÀ
# =============================================================================

def load_config_from_file(file_path: str) -> BulletinConfig:
    """Carica la configurazione da file JSON."""
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    return BulletinConfig(
        width=data.get("width", 2400),
        height=data.get("height", 1600),
        background_color=data.get("background_color", "#0F172A"),
        accent_color=data.get("accent_color", "#3B82F6"),
        text_color=data.get("text_color", "#F8FAFC"),
        secondary_text=data.get("secondary_text", "#94A3B8"),
        card_bg=data.get("card_bg", "#1E293B"),
        logo_path=data.get("logo_path"),
        logo_bg_replace=data.get("logo_bg_replace", False),
        logo_bg_color=data.get("logo_bg_color"),
        organization=data.get("organization", "Security Operations Center"),
        title=data.get("title", "Bollettino di Sicurezza"),
        date=data.get("date") or datetime.now().strftime("%d/%m/%Y"),
        footer_text=data.get("footer_text", "Confidential - Internal Use Only")
    )


def load_bulletins_from_file(file_path: str) -> list[dict]:
    """Carica i bollettini da file JSON."""
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("bulletins") or data.get("items") or []
    raise ValueError("Formato JSON non valido")


def process_batch(input_dir: str, output_dir: str, config: Optional[BulletinConfig] = None):
    """Processa tutti i file JSON in una directory."""
    os.makedirs(output_dir, exist_ok=True)
    json_files = file_glob.glob(os.path.join(input_dir, "*.json"))

    if not json_files:
        print(f"Nessun file JSON trovato in {input_dir}")
        return

    generator = SecurityBulletinGenerator(config)
    print(f"\n📂 Trovati {len(json_files)} file JSON in {input_dir}")

    for json_file in json_files:
        file_name = os.path.basename(json_file)
        print(f"🔄 {file_name}")
        bulletins = load_bulletins_from_file(json_file)
        base_name = os.path.splitext(file_name)[0]

        for i, bulletin in enumerate(bulletins):
            output_file = os.path.join(output_dir, f"{base_name}.png") if len(bulletins) == 1 else os.path.join(output_dir, f"{base_name}_{i+1:02d}.png")
            generator.generate_from_dict(bulletin, output_file)
            print(f"  ✅ {output_file}")


class SecurityBulletinGenerator:
    """Generatore di infografiche per bollettini di sicurezza."""
    
    # Mappature enum (calcolate una sola volta)
    _category_map = {c.value[0]: c for c in Category}
    _severity_map = {s.value[0]: s for s in Severity}
    
    def __init__(self, config: Optional[BulletinConfig] = None):
        self.config = config or BulletinConfig()
        self._load_fonts()
    
    def _load_fonts(self):
        """Carica i font Titillium Web dalla cartella fonts/."""
        script_dir = os.path.dirname(os.path.abspath(__file__))
        fonts_dir = os.path.join(script_dir, "fonts")

        font_bold = os.path.join(fonts_dir, "TitilliumWeb-Bold.ttf")
        font_semibold = os.path.join(fonts_dir, "TitilliumWeb-SemiBold.ttf")
        font_regular = os.path.join(fonts_dir, "TitilliumWeb-Regular.ttf")

        fallback_paths = [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/System/Library/Fonts/Helvetica.ttc",
            "C:/Windows/Fonts/arial.ttf",
        ]

        self.font_title = None
        self.font_heading = None
        self.font_bold = None
        self.font_body = None
        self.font_cve = None
        self.font_tag = None
        self.font_small = None

        if os.path.exists(font_bold):
            try:
                self.font_title = ImageFont.truetype(font_bold, 90)
                self.font_heading = ImageFont.truetype(font_semibold if os.path.exists(font_semibold) else font_bold, 56)
                self.font_bold = ImageFont.truetype(font_bold, 52)
            except Exception as e:
                print(f"⚠️  Errore caricamento font bold: {e}")

        if os.path.exists(font_regular):
            try:
                self.font_body = ImageFont.truetype(font_regular, 52)
                self.font_cve = ImageFont.truetype(font_regular, 56)
                self.font_tag = ImageFont.truetype(font_regular, 44)
                self.font_small = ImageFont.truetype(font_regular, 36)
            except Exception as e:
                print(f"⚠️  Errore caricamento font regular: {e}")

        # Fallback se Titillium non disponibile (dimensioni 2x)
        if not self.font_title or not self.font_body:
            print("⚠️  Font Titillium Web non trovati, uso fallback di sistema")
            for path in fallback_paths:
                if os.path.exists(path):
                    try:
                        if not self.font_title:
                            self.font_title = ImageFont.truetype(path, 90)
                            self.font_heading = ImageFont.truetype(path, 56)
                            self.font_bold = ImageFont.truetype(path, 52)
                        if not self.font_body:
                            self.font_body = ImageFont.truetype(path, 36)
                            self.font_small = ImageFont.truetype(path, 28)
                        break
                    except:
                        continue

        # Ultimo fallback ai font di default PIL
        if not self.font_title:
            self.font_title = ImageFont.load_default()
            self.font_heading = ImageFont.load_default()
            self.font_bold = ImageFont.load_default()
        if not self.font_body:
            self.font_body = ImageFont.load_default()
            self.font_small = ImageFont.load_default()
    
    def _hex_to_rgb(self, hex_color: str) -> tuple[int, int, int]:
        """Converte colore HEX in RGB."""
        hex_color = hex_color.lstrip('#')
        return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
    
    def _blend_colors(self, color1: tuple, color2: tuple, factor: float) -> tuple:
        """Miscela due colori RGB con un fattore (0.0 = color1, 1.0 = color2)."""
        return tuple(int(c1 + (c2 - c1) * factor) for c1, c2 in zip(color1, color2))
    
    def _draw_gradient_rounded_rect(self, image: Image, coords: tuple, radius: int,
                                     base_color: str, accent_color: str, gradient_width: int = 300):
        """Disegna un rettangolo con angoli arrotondati e gradiente orizzontale."""
        x1, y1, x2, y2 = coords
        base_rgb = self._hex_to_rgb(base_color)
        accent_rgb = self._hex_to_rgb(accent_color)
        width, height = x2 - x1, y2 - y1
        
        gradient_img = Image.new('RGBA', (width, height), (0, 0, 0, 0))
        gradient_draw = ImageDraw.Draw(gradient_img)
        gradient_draw.rounded_rectangle((0, 0, width, height), radius=radius, fill=base_rgb)
        
        for i in range(min(gradient_width, width)):
            factor = 1.0 - (i / gradient_width)
            blended = self._blend_colors(base_rgb, accent_rgb, factor * 0.18)
            gradient_draw.line([(i, radius), (i, height - radius)], fill=blended)
        
        image.paste(gradient_img, (x1, y1), gradient_img)
    
    def _draw_rounded_rect(self, draw: ImageDraw, coords: tuple, radius: int, 
                           fill: str, outline: Optional[str] = None, width: int = 0):
        """Disegna un rettangolo con angoli arrotondati."""
        draw.rounded_rectangle(coords, radius=radius, fill=self._hex_to_rgb(fill), 
                               outline=self._hex_to_rgb(outline) if outline else None, width=width)
    
    def _draw_severity_badge(self, draw: ImageDraw, x: int, y: int,
                             severity: Severity, width: int = 320):
        """Disegna il badge della severity."""
        _, color = severity.value
        badge_height = 90
        self._draw_rounded_rect(draw, (x, y, x + width, y + badge_height), radius=45, fill=color)

        text = severity.name
        bbox = draw.textbbox((0, 0), text, font=self.font_heading)
        text_x = x + (width - bbox[2] + bbox[0]) // 2
        text_y = y + (badge_height - bbox[3] + bbox[1]) // 2 - bbox[1]
        draw.text((text_x, text_y), text, fill="#FFFFFF", font=self.font_heading)
    
    def _draw_tag(self, draw: ImageDraw, x: int, y: int, tag: str, 
                  compact: bool = False, severity_color: str = None) -> int:
        """Disegna un tag e restituisce la larghezza occupata."""
        padding_x, tag_height, radius = (28, 52, 26) if compact else (40, 68, 34)
        font = self.font_small if compact else self.font_tag

        bbox = draw.textbbox((0, 0), tag, font=font)
        tag_width = bbox[2] - bbox[0] + padding_x * 2
        ref_bbox = draw.textbbox((0, 0), "Ayg", font=font)

        # Background e bordo colorati con severity
        if severity_color:
            severity_rgb = self._hex_to_rgb(severity_color)
            bg_color = "#{:02x}{:02x}{:02x}".format(*[int(c * 0.35) for c in severity_rgb])
            self._draw_rounded_rect(draw, (x, y, x + tag_width, y + tag_height),
                                    radius=radius, fill=bg_color, outline=severity_color, width=3)
        else:
            self._draw_rounded_rect(draw, (x, y, x + tag_width, y + tag_height),
                                    radius=radius, fill="#374151")

        text_y = y + (tag_height - ref_bbox[3] + ref_bbox[1]) // 2 - ref_bbox[1] + 4
        draw.text((x + padding_x, text_y), tag,
                  fill=self._hex_to_rgb(self.config.text_color), font=font)

        return tag_width + (12 if compact else 16)
    
    def _is_dark_pixel(self, r: int, g: int, b: int, threshold: int = 30) -> bool:
        return r < threshold and g < threshold and b < threshold
    
    def _is_light_pixel(self, r: int, g: int, b: int, threshold: int = 225) -> bool:
        return r > threshold and g > threshold and b > threshold
    
    def _replace_logo_background(self, logo: Image) -> Image:
        """Sostituisce lo sfondo del logo con il colore di background."""
        bg_rgb = self._hex_to_rgb(self.config.background_color)
        pixels = logo.load()
        target = self.config.logo_bg_color.lower() if self.config.logo_bg_color else None
        
        for py in range(logo.height):
            for px in range(logo.width):
                r, g, b, a = pixels[px, py]
                should_replace = False
                
                if target in ("black", "dark", "nero", "scuro"):
                    should_replace = self._is_dark_pixel(r, g, b)
                elif target in ("white", "light", "bianco", "chiaro"):
                    should_replace = self._is_light_pixel(r, g, b)
                elif target and target.startswith("#"):
                    target_rgb = self._hex_to_rgb(self.config.logo_bg_color)
                    should_replace = all(abs(c1 - c2) < 30 for c1, c2 in zip((r, g, b), target_rgb))
                else:
                    should_replace = self._is_dark_pixel(r, g, b) or self._is_light_pixel(r, g, b)
                
                if should_replace:
                    pixels[px, py] = (*bg_rgb, a)
        return logo
    
    def _load_and_process_logo(self) -> tuple[Optional[Image.Image], int]:
        """Carica e processa il logo, restituisce (logo, logo_end_x)."""
        if not self.config.logo_path or not os.path.exists(self.config.logo_path):
            return None, MARGIN
        
        logo = Image.open(self.config.logo_path).convert("RGBA")
        logo.thumbnail((LOGO_MAX_SIZE, LOGO_MAX_SIZE))
        
        if self.config.logo_bg_replace:
            logo = self._replace_logo_background(logo)
        
        return logo, MARGIN + logo.width + 40

    def _draw_header(self, draw: ImageDraw, image: Image) -> int:
        """Disegna l'header dell'infografica. Ritorna la Y position dopo l'header."""
        draw.rectangle((0, 0, self.config.width, HEADER_LINE_HEIGHT),
                       fill=self._hex_to_rgb(self.config.accent_color))

        org_bbox = draw.textbbox((0, 0), self.config.organization, font=self.font_body)
        org_height = org_bbox[3] - org_bbox[1]

        logo, logo_end_x = self._load_and_process_logo()
        if logo:
            org_bottom_y = HEADER_Y_START + 125 + org_height
            logo_y = org_bottom_y - logo.height + 10
            image.paste(logo, (MARGIN, logo_y), logo)

        draw.text((logo_end_x, HEADER_Y_START), self.config.title,
                  fill=self._hex_to_rgb(self.config.text_color), font=self.font_title)

        draw.text((logo_end_x, HEADER_Y_START + 125), self.config.organization,
                  fill=self._hex_to_rgb(self.config.secondary_text), font=self.font_body)

        if self.config.date:
            date_bbox = draw.textbbox((0, 0), self.config.date, font=self.font_heading)
            date_x = self.config.width - (date_bbox[2] - date_bbox[0]) - MARGIN
            draw.text((date_x, HEADER_Y_START + 30), self.config.date,
                      fill=self._hex_to_rgb(self.config.text_color), font=self.font_heading)

        draw.line((MARGIN, 260, self.config.width - MARGIN, 260),
                  fill=self._hex_to_rgb("#334155"), width=4)

        return HEADER_END_Y
    
    def _get_card_spacing(self, compact: bool = False, has_tags: bool = False) -> dict:
        """Restituisce le spaziature per la card in base alla modalità."""
        if compact:
            return {
                'padding_top': 30,
                'padding_bottom': 35,
                'tag_section_height': 70 if has_tags else 0,
                'spacing_category': 60,
                'spacing_product': 55,
                'spacing_cve': 70,
                'spacing_cve_desc': 70,
                'spacing_no_cve': 80,
                'line_height': 44,
                'max_desc_lines': 5,
                'badge_margin': 35,
                'badge_width': 280,
            }
        else:
            return {
                'padding_top': 40,
                'padding_bottom': 50,
                'tag_section_height': 90 if has_tags else 0,
                'spacing_category': 80,
                'spacing_product': 70,
                'spacing_cve': 90,
                'spacing_cve_desc': 80,
                'spacing_no_cve': 100,
                'line_height': 58,
                'max_desc_lines': 6,
                'badge_margin': 50,
                'badge_width': 320,
            }

    def _wrap_description(self, description: str, card_width: int, compact: bool = False) -> list[str]:
        """Wrappa la descrizione rispettando i \\n espliciti."""
        # In compact font più piccolo (36pt vs 52pt) → più caratteri per pixel → divisore minore
        wrap_width = int(card_width / (16 if compact else 22))
        wrapped = []
        for paragraph in description.split('\n'):
            paragraph = paragraph.strip()
            if paragraph:
                wrapped.extend(textwrap.wrap(paragraph, width=wrap_width))
            else:
                wrapped.append('')
        return wrapped

    def _calculate_card_height(self, item: BulletinItem, card_width: int, compact: bool = False) -> int:
        """Calcola l'altezza necessaria per la card in base al contenuto."""
        s = self._get_card_spacing(compact, bool(item.tags))
        
        content_height = s['padding_top'] + s['spacing_category'] + s['spacing_product']

        if item.cve_id:
            content_height += s['spacing_cve'] + s['spacing_cve_desc']
        else:
            content_height += s['spacing_no_cve']

        wrapped_desc = self._wrap_description(item.description, card_width, compact)
        desc_lines = min(len(wrapped_desc), s['max_desc_lines'])
        content_height += desc_lines * s['line_height']

        return content_height + s['tag_section_height'] + s['padding_bottom']

    def _draw_item_card(self, draw: ImageDraw, image: Image, x: int, y: int,
                        item: BulletinItem, card_width: int, min_height: int = 0, compact: bool = False) -> int:
        """
        Disegna una card per un singolo item con layout a larghezza piena.

        Args:
            image: Oggetto Image per disegnare il gradiente
            min_height: Altezza minima della card (per espanderla quando non c'è immagine)
            compact: Se True, usa spaziature ridotte (per quando c'è un'immagine allegata)

        Returns:
            La posizione Y finale dopo la card (e l'eventuale immagine)
        """
        _, severity_color = item.severity.value
        inner_x = x + 50
        
        # Ottieni spaziature e wrappa descrizione
        s = self._get_card_spacing(compact, bool(item.tags))
        wrapped_desc = self._wrap_description(item.description, card_width, compact)
        desc_lines = min(len(wrapped_desc), s['max_desc_lines'])

        # Calcola altezza card
        content_height = s['padding_top'] + s['spacing_category'] + s['spacing_product']
        if item.cve_id:
            content_height += s['spacing_cve'] + s['spacing_cve_desc']
        else:
            content_height += s['spacing_no_cve']
        content_height += desc_lines * s['line_height']
        
        card_height = content_height + s['tag_section_height'] + s['padding_bottom']
        if min_height > 0 and card_height < min_height:
            card_height = min_height

        # Card background con gradiente sfumato dal colore severity
        self._draw_gradient_rounded_rect(image, (x, y, x + card_width, y + card_height),
                                         radius=24, base_color=self.config.card_bg,
                                         accent_color=severity_color, gradient_width=400)
        
        # Ridisegna il draw context dopo aver modificato l'immagine
        draw = ImageDraw.Draw(image)

        # Bordo colorato per severity (a sinistra)
        draw.rectangle((x, y + 24, x + 10, y + card_height - 24),
                       fill=self._hex_to_rgb(severity_color))

        # Contenuto della card
        inner_y = y + s['padding_top']

        # Categoria
        _, category_label = item.category.value
        draw.text((inner_x, inner_y), category_label.upper(),
                  fill=self._hex_to_rgb(self.config.accent_color),
                  font=self.font_bold)

        # Severity badge
        self._draw_severity_badge(
            draw, 
            x + card_width - s['badge_width'] - s['badge_margin'], 
            y + s['badge_margin'],
            item.severity, 
            width=s['badge_width']
        )

        # Prodotto
        inner_y += s['spacing_category']
        product_text = f"{item.product} v{item.version}" if item.version else item.product
        draw.text((inner_x, inner_y), product_text,
                  fill=self._hex_to_rgb(self.config.text_color),
                  font=self.font_heading)

        # CVE ID
        if item.cve_id:
            inner_y += s['spacing_cve']
            draw.text((inner_x, inner_y), item.cve_id,
                      fill=self._hex_to_rgb("#EF4444"),
                      font=self.font_cve if not compact else self.font_body)
            inner_y += s['spacing_cve_desc']
        else:
            inner_y += s['spacing_no_cve']

        # Descrizione
        desc_font = self.font_body if not compact else self.font_small
        for line in wrapped_desc[:s['max_desc_lines']]:
            draw.text((inner_x, inner_y), line,
                      fill=self._hex_to_rgb(self.config.secondary_text),
                      font=desc_font)
            inner_y += s['line_height']

        # Tags
        if item.tags:
            tag_height = 68 if not compact else 52
            tag_y = y + card_height - s['padding_bottom'] - tag_height
            tag_x = inner_x
            max_tags = 6 if not compact else 4
            for tag in item.tags[:max_tags]:
                if tag_x + 200 > x + card_width - 40:
                    break
                tag_x += self._draw_tag(draw, tag_x, tag_y, tag, compact=compact, severity_color=severity_color)

        return y + card_height + 40
    
    def _draw_footer(self, draw: ImageDraw, height: int):
        """Disegna il footer dell'infografica."""
        y = height - MARGIN
        draw.line((MARGIN, y - 30, self.config.width - MARGIN, y - 30),
                  fill=self._hex_to_rgb("#334155"), width=2)
        
        bbox = draw.textbbox((0, 0), self.config.footer_text, font=self.font_small)
        x = (self.config.width - bbox[2] + bbox[0]) // 2
        draw.text((x, y), self.config.footer_text, 
                  fill=self._hex_to_rgb(self.config.secondary_text), font=self.font_small)
    
    def _load_attached_image(self, item: BulletinItem, card_width: int, available_height: int) -> tuple[Optional[Image.Image], bool]:
        """Carica e ridimensiona l'immagine allegata. Ritorna (immagine, compact_mode)."""
        if not item.image_path or not os.path.exists(item.image_path):
            return None, False
        
        attached_img = Image.open(item.image_path).convert("RGBA")
        card_height = self._calculate_card_height(item, card_width, compact=True)
        space_for_image = available_height - card_height - 40
        
        if space_for_image < 150:
            print(f"⚠️  Spazio insufficiente per l'immagine, verrà omessa")
            return None, False
        
        max_img_width = card_width - MARGIN
        img_ratio = attached_img.width / attached_img.height
        new_width = min(attached_img.width, max_img_width)
        new_height = int(new_width / img_ratio)
        
        if new_height > space_for_image:
            new_height = space_for_image
            new_width = int(new_height * img_ratio)
        
        return attached_img.resize((new_width, new_height), Image.LANCZOS), True

    def generate(self, item: BulletinItem, output_path: Optional[str] = None) -> Image:
        """Genera l'infografica per un singolo bollettino di sicurezza."""
        card_width = self.config.width - (MARGIN * 2)
        
        image = Image.new('RGB', (self.config.width, self.config.height),
                          self._hex_to_rgb(self.config.background_color))
        draw = ImageDraw.Draw(image)

        y_offset = self._draw_header(draw, image)
        available_height = self.config.height - y_offset - FOOTER_HEIGHT - 40

        attached_img, compact_mode = self._load_attached_image(item, card_width, available_height)
        
        if attached_img:
            card_min_height = self._calculate_card_height(item, card_width, compact=True)
        else:
            card_min_height = available_height

        card_end_y = self._draw_item_card(draw, image, MARGIN, y_offset, item, card_width, card_min_height, compact=compact_mode)

        if attached_img:
            img_x = MARGIN + (card_width - attached_img.width) // 2
            image.paste(attached_img, (img_x, card_end_y), attached_img)

        self._draw_footer(draw, self.config.height)

        if output_path:
            image.save(output_path, quality=95)
            print(f"✅ Infografica salvata in: {output_path}")

        return image
    
    def generate_from_dict(self, data: dict, output_path: Optional[str] = None) -> Image:
        """Genera infografica da un dizionario."""
        item = BulletinItem(
            category=self._category_map.get(data["category"].lower(), Category.ADVISORY),
            severity=self._severity_map.get(data["severity"].lower(), Severity.MEDIUM),
            product=data["product"],
            description=data["description"],
            tags=data.get("tags", []),
            cve_id=data.get("cve_id"),
            version=data.get("version"),
            image_path=data.get("image")
        )
        return self.generate(item, output_path)


# =============================================================================
# MAIN - INTERFACCIA CLI
# =============================================================================

def create_parser():
    """Crea e configura il parser degli argomenti CLI."""
    parser = argparse.ArgumentParser(
        description="AlertForge - Genera infografiche professionali per bollettini di sicurezza",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Esempi di utilizzo:

  # Genera bollettino da singolo file JSON
  python alertforge.py -i bulletins.json -o bollettino.png

  # Usa file di configurazione personalizzato
  python alertforge.py -i bulletins.json -o bollettino.png -c config.json

  # Modalità batch: processa tutti i JSON in una directory
  python alertforge.py --batch input_dir/ -od output_dir/

  # Batch con configurazione personalizzata
  python alertforge.py --batch input_dir/ -od output_dir/ -c config.json

Per maggiori informazioni: https://github.com/your-repo/alertforge
        """
    )

    # Argomenti principali
    parser.add_argument(
        "-i", "--input",
        type=str,
        help="File JSON contenente i bollettini (modalità singolo file)"
    )

    parser.add_argument(
        "-o", "--output",
        type=str,
        help="Nome file output PNG (modalità singolo file)"
    )

    parser.add_argument(
        "-c", "--config",
        type=str,
        help="File JSON di configurazione (colori, dimensioni, testi, ecc.)"
    )

    # Modalità batch
    parser.add_argument(
        "--batch",
        type=str,
        metavar="DIR",
        help="Directory contenente file JSON da processare in batch"
    )

    parser.add_argument(
        "-od", "--output-dir",
        type=str,
        default="output",
        help="Directory output per modalità batch (default: output/)"
    )

    # Opzioni aggiuntive
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Output verboso"
    )

    parser.add_argument(
        "--version",
        action="version",
        version="AlertForge v1.0"
    )

    return parser


def main():
    """Funzione principale."""
    parser = create_parser()
    args = parser.parse_args()

    print("\n" + "=" * 60)
    print("  🔒 AlertForge v1.0")
    print("=" * 60)

    # Carica configurazione
    config_file = args.config or ("config.json" if os.path.exists("config.json") else None)
    
    if config_file:
        print(f"\n📋 Config: {config_file}")
        config = load_config_from_file(config_file)
    else:
        config = BulletinConfig(date=datetime.now().strftime("%d/%m/%Y"))

    # Modalità batch
    if args.batch:
        print(f"\n🔄 Batch: {args.batch} → {args.output_dir}")
        process_batch(args.batch, args.output_dir, config)
        sys.exit(0)

    # Modalità singolo file
    input_file = args.input or ("bulletins.json" if os.path.exists("bulletins.json") else None)
    
    if not input_file or not args.output:
        print("\n❌ Specificare --input e --output, oppure --batch")
        parser.print_help()
        sys.exit(1)

    print(f"\n📄 Input: {input_file}")
    bulletins = load_bulletins_from_file(input_file)
    print(f"✅ {len(bulletins)} bollettini")

    generator = SecurityBulletinGenerator(config)

    if len(bulletins) == 1:
        image = generator.generate_from_dict(bulletins[0], args.output)
        print(f"✅ {args.output} ({image.size[0]}x{image.size[1]} px)")
    else:
        output_base, output_ext = os.path.splitext(args.output)
        output_ext = output_ext or ".png"

        for i, bulletin in enumerate(bulletins, 1):
            output_file = f"{output_base}_{i:02d}{output_ext}"
            image = generator.generate_from_dict(bulletin, output_file)
            print(f"✅ [{i}/{len(bulletins)}] {output_file}")

    print()


if __name__ == "__main__":
    main()
