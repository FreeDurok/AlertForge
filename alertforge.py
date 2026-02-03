#!/usr/bin/env python3
"""
AlertForge - Security Bulletin Infographic Generator
Genera infografiche professionali per bollettini di sicurezza.

Autore: Security Team
Versione: 1.0
"""

from PIL import Image, ImageDraw, ImageFont
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum
import textwrap
import io
import os
import json
import argparse
import sys
import glob as file_glob
from datetime import datetime


class Severity(Enum):
    """Livelli di severity con colori associati."""
    CRITICAL = ("critical", "#DC2626", "#FEE2E2", "⚠️")  # Rosso
    HIGH = ("high", "#EA580C", "#FFEDD5", "🔴")           # Arancione
    MEDIUM = ("medium", "#CA8A04", "#FEF9C3", "🟡")      # Giallo
    LOW = ("low", "#16A34A", "#DCFCE7", "🟢")            # Verde
    INFO = ("info", "#2563EB", "#DBEAFE", "ℹ️")          # Blu


class Category(Enum):
    """Categorie di bollettini."""
    AGGIORNAMENTI = ("aggiornamenti", "🔄", "Aggiornamenti")
    VULNERABILITA = ("vulnerabilita", "🛡️", "Vulnerabilità")
    PATCH = ("patch", "🩹", "Patch")
    ADVISORY = ("advisory", "📢", "Advisory")
    INCIDENT = ("incident", "🚨", "Incident")


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


# =============================================================================
# FUNZIONI DI UTILITÀ E VALIDAZIONE
# =============================================================================

def validate_bulletin_data(data: dict, index: int = 0) -> tuple[bool, str]:
    """
    Valida un singolo bollettino.

    Returns:
        Tupla (is_valid, error_message)
    """
    required_fields = ["category", "severity", "product", "description"]

    # Verifica campi obbligatori
    for field in required_fields:
        if field not in data or not data[field]:
            return False, f"Bollettino #{index}: Campo obbligatorio '{field}' mancante o vuoto"

    # Valida category
    valid_categories = [c.value[0] for c in Category]
    if data["category"].lower() not in valid_categories:
        return False, f"Bollettino #{index}: Category '{data['category']}' non valida. Usare: {', '.join(valid_categories)}"

    # Valida severity
    valid_severities = [s.value[0] for s in Severity]
    if data["severity"].lower() not in valid_severities:
        return False, f"Bollettino #{index}: Severity '{data['severity']}' non valida. Usare: {', '.join(valid_severities)}"

    # Valida product
    if len(data["product"].strip()) < 2:
        return False, f"Bollettino #{index}: Il nome del prodotto deve essere di almeno 2 caratteri"

    # Valida description
    if len(data["description"].strip()) < 10:
        return False, f"Bollettino #{index}: La descrizione deve essere di almeno 10 caratteri"

    # Valida CVE ID se presente
    if "cve_id" in data and data["cve_id"]:
        cve = data["cve_id"].upper()
        if not cve.startswith("CVE-"):
            return False, f"Bollettino #{index}: CVE ID deve iniziare con 'CVE-'"

    return True, ""


def load_json_file(file_path: str) -> tuple[Optional[dict], Optional[str]]:
    """
    Carica un file JSON con gestione errori.

    Returns:
        Tupla (data, error_message)
    """
    try:
        if not os.path.exists(file_path):
            return None, f"File non trovato: {file_path}"

        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data, None
    except json.JSONDecodeError as e:
        return None, f"Errore parsing JSON in {file_path}: {e}"
    except Exception as e:
        return None, f"Errore caricamento file {file_path}: {e}"


def load_config_from_file(file_path: str) -> tuple[Optional[BulletinConfig], Optional[str]]:
    """
    Carica la configurazione da file JSON.

    Returns:
        Tupla (config, error_message)
    """
    data, error = load_json_file(file_path)
    if error:
        return None, error

    try:
        # Data: se null o non specificata, usa la data corrente
        config_date = data.get("date")
        if not config_date:
            config_date = datetime.now().strftime("%d/%m/%Y")

        # Crea config con valori dal file (sovrascrive i default)
        config = BulletinConfig(
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
            date=config_date,
            footer_text=data.get("footer_text", "Confidential - Internal Use Only")
        )
        return config, None
    except Exception as e:
        return None, f"Errore creazione configurazione: {e}"


def load_bulletins_from_file(file_path: str) -> tuple[Optional[list[dict]], Optional[str]]:
    """
    Carica i bollettini da file JSON.

    Il file può contenere:
    - Una lista di bollettini: [{"category": ..., "severity": ...}, ...]
    - Un dizionario con chiave "bulletins": {"bulletins": [...]}

    Returns:
        Tupla (bulletins_list, error_message)
    """
    data, error = load_json_file(file_path)
    if error:
        return None, error

    # Gestisci diversi formati
    bulletins = []
    if isinstance(data, list):
        bulletins = data
    elif isinstance(data, dict):
        if "bulletins" in data:
            bulletins = data["bulletins"]
        elif "items" in data:
            bulletins = data["items"]
        else:
            return None, f"Formato JSON non valido. Atteso una lista o un dict con chiave 'bulletins' o 'items'"
    else:
        return None, f"Formato JSON non valido. Atteso una lista o un dizionario"

    # Valida ogni bollettino
    for i, bulletin in enumerate(bulletins):
        is_valid, error_msg = validate_bulletin_data(bulletin, i + 1)
        if not is_valid:
            return None, error_msg

    return bulletins, None


def process_batch(input_dir: str, output_dir: str, config: Optional[BulletinConfig] = None) -> tuple[int, int, list[str]]:
    """
    Processa tutti i file JSON in una directory e genera i bollettini.
    Ogni bollettino genera una singola immagine.

    Args:
        input_dir: Directory contenente i file JSON dei bollettini
        output_dir: Directory dove salvare le immagini generate
        config: Configurazione opzionale (se None, usa default)

    Returns:
        Tupla (successi, fallimenti, lista_errori)
    """
    # Crea output_dir se non esiste
    os.makedirs(output_dir, exist_ok=True)

    # Trova tutti i file JSON
    json_files = file_glob.glob(os.path.join(input_dir, "*.json"))

    if not json_files:
        return 0, 0, [f"Nessun file JSON trovato in {input_dir}"]

    generator = SecurityBulletinGenerator(config)
    successes = 0
    failures = 0
    errors = []

    print(f"\n📂 Trovati {len(json_files)} file JSON in {input_dir}")
    print("=" * 60)

    for json_file in json_files:
        file_name = os.path.basename(json_file)
        print(f"\n🔄 Processando: {file_name}")

        # Carica bollettini
        bulletins, error = load_bulletins_from_file(json_file)
        if error:
            failures += 1
            error_msg = f"❌ {file_name}: {error}"
            errors.append(error_msg)
            print(error_msg)
            continue

        # Genera output filename base
        base_name = os.path.splitext(file_name)[0]

        # Genera un'immagine per ogni bollettino
        for i, bulletin in enumerate(bulletins):
            if len(bulletins) == 1:
                output_file = os.path.join(output_dir, f"{base_name}.png")
            else:
                output_file = os.path.join(output_dir, f"{base_name}_{i+1:02d}.png")

            try:
                generator.generate_from_dict(bulletin, output_file)
                successes += 1
                print(f"✅ Generato: {output_file}")
            except Exception as e:
                failures += 1
                error_msg = f"❌ {file_name} bollettino #{i+1}: Errore generazione: {e}"
                errors.append(error_msg)
                print(error_msg)

    return successes, failures, errors


class SecurityBulletinGenerator:
    """Generatore di infografiche per bollettini di sicurezza."""
    
    def __init__(self, config: Optional[BulletinConfig] = None):
        self.config = config or BulletinConfig()
        self._load_fonts()
    
    def _load_fonts(self):
        """Carica i font Titillium Web dalla cartella fonts/."""
        # Percorso base dello script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        fonts_dir = os.path.join(script_dir, "fonts")

        # Font Titillium Web
        font_bold = os.path.join(fonts_dir, "TitilliumWeb-Bold.ttf")
        font_semibold = os.path.join(fonts_dir, "TitilliumWeb-SemiBold.ttf")
        font_regular = os.path.join(fonts_dir, "TitilliumWeb-Regular.ttf")

        # Fallback a font di sistema se Titillium non disponibile
        fallback_paths = [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/System/Library/Fonts/Helvetica.ttc",
            "C:/Windows/Fonts/arial.ttf",
        ]

        self.font_title = None
        self.font_date = None       # Per la data header (grande)
        self.font_product = None    # Per il titolo prodotto nella card
        self.font_heading = None    # Per severity badge
        self.font_body = None       # Per descrizione
        self.font_cve = None        # Per CVE ID
        self.font_tag = None        # Per i tag

        # Carica Titillium Web Bold per titoli (dimensioni 2x per alta risoluzione)
        if os.path.exists(font_bold):
            try:
                self.font_title = ImageFont.truetype(font_bold, 90)       # Header principale
                self.font_date = ImageFont.truetype(font_bold, 88)        # Data (ancora più grande)
                self.font_product = ImageFont.truetype(font_semibold if os.path.exists(font_semibold) else font_bold, 76)  # Titolo prodotto (più grande)
                self.font_heading = ImageFont.truetype(font_semibold if os.path.exists(font_semibold) else font_bold, 56)  # Badge severity
            except Exception as e:
                print(f"⚠️  Errore caricamento font bold: {e}")

        # Carica Titillium Web Regular per body (dimensioni aumentate)
        if os.path.exists(font_regular):
            try:
                self.font_body = ImageFont.truetype(font_regular, 52)     # Descrizione (più grande)
                self.font_cve = ImageFont.truetype(font_regular, 56)      # CVE ID (più grande)
                self.font_tag = ImageFont.truetype(font_regular, 44)      # Tag (più grande)
                self.font_small = ImageFont.truetype(font_regular, 36)    # Testo piccolo (categoria, footer)
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
        """Disegna un rettangolo con angoli arrotondati e gradiente orizzontale sul lato sinistro."""
        from PIL import ImageDraw
        
        x1, y1, x2, y2 = coords
        base_rgb = self._hex_to_rgb(base_color)
        accent_rgb = self._hex_to_rgb(accent_color)
        
        # Crea un'immagine temporanea per il gradiente
        width = x2 - x1
        height = y2 - y1
        gradient_img = Image.new('RGBA', (width, height), (0, 0, 0, 0))
        gradient_draw = ImageDraw.Draw(gradient_img)
        
        # Disegna il rettangolo base
        gradient_draw.rounded_rectangle((0, 0, width, height), radius=radius, fill=base_rgb)
        
        # Applica gradiente orizzontale sul lato sinistro
        for i in range(min(gradient_width, width)):
            # Fattore di sfumatura: più intenso a sinistra, sfuma verso destra
            factor = 1.0 - (i / gradient_width)
            # Mescola il colore accent con il base (opacità ~15% max)
            blend_factor = factor * 0.18
            blended = self._blend_colors(base_rgb, accent_rgb, blend_factor)
            
            # Disegna linea verticale
            gradient_draw.line([(i, radius), (i, height - radius)], fill=blended)
        
        # Incolla sul canvas principale
        image.paste(gradient_img, (x1, y1), gradient_img)
    
    def _draw_rounded_rect(self, draw: ImageDraw, coords: tuple, radius: int, 
                           fill: str, outline: Optional[str] = None, width: int = 0):
        """Disegna un rettangolo con angoli arrotondati."""
        x1, y1, x2, y2 = coords
        fill_rgb = self._hex_to_rgb(fill)
        outline_rgb = self._hex_to_rgb(outline) if outline else None
        
        draw.rounded_rectangle(coords, radius=radius, fill=fill_rgb, 
                               outline=outline_rgb, width=width)
    
    def _draw_severity_badge(self, draw: ImageDraw, x: int, y: int,
                             severity: Severity, width: int = 320):
        """Disegna il badge della severity - grande e in risalto."""
        _, color, bg_color, _ = severity.value
        badge_height = 90

        # Badge background - grande e prominente
        self._draw_rounded_rect(draw, (x, y, x + width, y + badge_height),
                                radius=45, fill=color)

        # Testo severity - BOLD, centrato sia orizzontalmente che verticalmente
        text = severity.name
        bbox = draw.textbbox((0, 0), text, font=self.font_heading)  # Font bold/semibold
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]
        text_x = x + (width - text_width) // 2
        text_y = y + (badge_height - text_height) // 2 - bbox[1]
        draw.text((text_x, text_y), text, fill="#FFFFFF", font=self.font_heading)
    
    def _draw_category_icon(self, draw: ImageDraw, x: int, y: int, 
                            category: Category, size: int = 50):
        """Disegna l'icona della categoria."""
        _, icon, label = category.value
        
        # Cerchio di sfondo
        self._draw_rounded_rect(draw, (x, y, x + size, y + size), 
                                radius=size // 2, fill=self.config.accent_color)
        
        # Label sotto l'icona
        bbox = draw.textbbox((0, 0), label, font=self.font_small)
        text_width = bbox[2] - bbox[0]
        text_x = x + (size - text_width) // 2
        draw.text((text_x, y + size + 5), label, 
                  fill=self._hex_to_rgb(self.config.secondary_text), 
                  font=self.font_small)
    
    def _draw_tag(self, draw: ImageDraw, x: int, y: int, tag: str, compact: bool = False) -> int:
        """Disegna un tag e restituisce la larghezza occupata."""
        if compact:
            padding_x = 28
            tag_height = 52
            radius = 26
            font = self.font_small
        else:
            padding_x = 40
            tag_height = 68
            radius = 34
            font = self.font_tag

        bbox = draw.textbbox((0, 0), tag, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]
        tag_width = text_width + padding_x * 2

        # Tag background
        self._draw_rounded_rect(draw, (x, y, x + tag_width, y + tag_height),
                                radius=radius, fill="#374151")

        # Tag text - centrato verticalmente (compensando l'offset del font)
        text_y = y + (tag_height - text_height) // 2 - bbox[1]
        draw.text((x + padding_x, text_y), tag,
                  fill=self._hex_to_rgb(self.config.text_color),
                  font=font)

        return tag_width + (16 if not compact else 12)
    
    def _draw_header(self, draw: ImageDraw, image: Image):
        """Disegna l'header dell'infografica."""
        # Linea decorativa in alto (dimensioni 2x)
        draw.rectangle((0, 0, self.config.width, 12),
                       fill=self._hex_to_rgb(self.config.accent_color))

        y_start = 60  # 30 * 2

        # Calcola prima le dimensioni del blocco testo per centrare il logo
        title_bbox = draw.textbbox((0, 0), self.config.title, font=self.font_title)
        title_height = title_bbox[3] - title_bbox[1]
        org_bbox = draw.textbbox((0, 0), self.config.organization, font=self.font_body)
        org_height = org_bbox[3] - org_bbox[1]
        # Il blocco testo va da y_start a y_start + 125 + org_height
        text_block_total_height = 125 + org_height

        # Logo se presente
        logo_end_x = 80  # 40 * 2
        if self.config.logo_path and os.path.exists(self.config.logo_path):
            try:
                logo = Image.open(self.config.logo_path)
                logo = logo.convert("RGBA")
                logo.thumbnail((160, 160))  # 80 * 2
                
                # Sostituisci sfondo del logo se abilitato nel config
                if self.config.logo_bg_replace:
                    bg_rgb = self._hex_to_rgb(self.config.background_color)
                    pixels = logo.load()
                    
                    # Determina quale colore sostituire
                    if self.config.logo_bg_color:
                        # Colore specificato dall'utente
                        target_color = self.config.logo_bg_color.lower()
                        if target_color in ("black", "dark", "nero", "scuro"):
                            # Sostituisci pixel scuri
                            for py in range(logo.height):
                                for px in range(logo.width):
                                    r, g, b, a = pixels[px, py]
                                    if r < 30 and g < 30 and b < 30:
                                        pixels[px, py] = (bg_rgb[0], bg_rgb[1], bg_rgb[2], a)
                        elif target_color in ("white", "light", "bianco", "chiaro"):
                            # Sostituisci pixel chiari
                            for py in range(logo.height):
                                for px in range(logo.width):
                                    r, g, b, a = pixels[px, py]
                                    if r > 225 and g > 225 and b > 225:
                                        pixels[px, py] = (bg_rgb[0], bg_rgb[1], bg_rgb[2], a)
                        elif target_color.startswith("#"):
                            # Colore hex specifico
                            target_rgb = self._hex_to_rgb(self.config.logo_bg_color)
                            tolerance = 30
                            for py in range(logo.height):
                                for px in range(logo.width):
                                    r, g, b, a = pixels[px, py]
                                    if (abs(r - target_rgb[0]) < tolerance and 
                                        abs(g - target_rgb[1]) < tolerance and 
                                        abs(b - target_rgb[2]) < tolerance):
                                        pixels[px, py] = (bg_rgb[0], bg_rgb[1], bg_rgb[2], a)
                    else:
                        # Auto-detect: sostituisci sia scuri che chiari (bordi dell'immagine)
                        for py in range(logo.height):
                            for px in range(logo.width):
                                r, g, b, a = pixels[px, py]
                                # Sostituisci pixel molto scuri
                                if r < 30 and g < 30 and b < 30:
                                    pixels[px, py] = (bg_rgb[0], bg_rgb[1], bg_rgb[2], a)
                                # Sostituisci pixel molto chiari
                                elif r > 225 and g > 225 and b > 225:
                                    pixels[px, py] = (bg_rgb[0], bg_rgb[1], bg_rgb[2], a)
                
                # Allinea il logo al bottom dell'organization (con leggero offset)
                org_bottom_y = y_start + 125 + org_height
                logo_y = org_bottom_y - logo.height + 10
                image.paste(logo, (80, logo_y), logo if logo.mode == 'RGBA' else None)
                logo_end_x = 80 + logo.width + 40
            except Exception as e:
                print(f"Errore caricamento logo: {e}")

        # Titolo
        draw.text((logo_end_x, y_start), self.config.title,
                  fill=self._hex_to_rgb(self.config.text_color),
                  font=self.font_title)

        # Organizzazione (più spazio per lettere con discendenti come 'g', 'y', 'p')
        draw.text((logo_end_x, y_start + 125), self.config.organization,
                  fill=self._hex_to_rgb(self.config.secondary_text),
                  font=self.font_body)

        # Data a destra - più grande
        if self.config.date:
            bbox = draw.textbbox((0, 0), self.config.date, font=self.font_heading)
            text_width = bbox[2] - bbox[0]
            draw.text((self.config.width - text_width - 80, y_start + 30),
                      self.config.date,
                      fill=self._hex_to_rgb(self.config.text_color),
                      font=self.font_heading)

        # Linea separatrice
        draw.line((80, 260, self.config.width - 80, 260),
                  fill=self._hex_to_rgb("#334155"), width=4)

        return 300  # Y position dopo header
    
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
        _, severity_color, _, _ = item.severity.value

        inner_x = x + 50
        
        # Spaziature diverse per modalità normale e compatta
        if compact:
            padding_top = 30
            padding_bottom = 35
            tag_section_height = 70 if item.tags else 0
            spacing_category = 60
            spacing_product = 55
            spacing_cve = 70  # Aumentato
            spacing_cve_desc = 70  # Aumentato
            spacing_no_cve = 80
            line_height = 44
            max_desc_lines = 3  # Meno righe in modalità compatta
        else:
            padding_top = 40
            padding_bottom = 50
            tag_section_height = 90 if item.tags else 0
            spacing_category = 80
            spacing_product = 70
            spacing_cve = 90
            spacing_cve_desc = 80
            spacing_no_cve = 100
            line_height = 58
            max_desc_lines = 6

        # Calcola altezza contenuto (senza tag)
        content_height = padding_top

        # Categoria + severity badge
        content_height += spacing_category

        # Prodotto
        content_height += spacing_product

        # CVE ID se presente
        if item.cve_id:
            content_height += spacing_cve + spacing_cve_desc
        else:
            content_height += spacing_no_cve

        # Descrizione
        wrap_width = int(card_width / 22)
        wrapped_desc = textwrap.wrap(item.description, width=wrap_width)
        desc_lines = min(len(wrapped_desc), max_desc_lines)
        content_height += desc_lines * line_height

        # Calcola altezza card totale (contenuto + spazio tag + padding)
        card_height = content_height + tag_section_height + padding_bottom
        
        # Se specificata un'altezza minima, usa quella (per espandere la card senza immagine)
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

        # Ora disegna il contenuto
        inner_y = y + padding_top

        # Prima riga: Categoria + Severity badge
        _, _, category_label = item.category.value
        draw.text((inner_x, inner_y), category_label.upper(),
                  fill=self._hex_to_rgb(self.config.accent_color),
                  font=self.font_body)  # Font più grande per la tipologia

        # Severity badge a destra (stesso margine dal top e dal right)
        badge_margin = 50 if not compact else 35
        badge_width = 320 if not compact else 280
        self._draw_severity_badge(draw, x + card_width - badge_width - badge_margin, y + badge_margin,
                                  item.severity, width=badge_width)

        # Prodotto
        inner_y += spacing_category
        product_text = item.product
        if item.version:
            product_text += f" v{item.version}"
        draw.text((inner_x, inner_y), product_text,
                  fill=self._hex_to_rgb(self.config.text_color),
                  font=self.font_heading)  # Sempre bold per il titolo

        # CVE ID se presente
        if item.cve_id:
            inner_y += spacing_cve
            draw.text((inner_x, inner_y), item.cve_id,
                      fill=self._hex_to_rgb("#EF4444"),
                      font=self.font_cve if not compact else self.font_body)
            inner_y += spacing_cve_desc
        else:
            inner_y += spacing_no_cve

        # Descrizione
        for line in wrapped_desc[:max_desc_lines]:
            draw.text((inner_x, inner_y), line,
                      fill=self._hex_to_rgb(self.config.secondary_text),
                      font=self.font_body if not compact else self.font_small)
            inner_y += line_height

        # Tags - sempre allineati al bottom della card
        if item.tags:
            tag_height = 68 if not compact else 52
            tag_y = y + card_height - padding_bottom - tag_height
            tag_x = inner_x
            max_tags = 6 if not compact else 4
            for tag in item.tags[:max_tags]:
                if tag_x + 200 > x + card_width - 40:
                    break
                tag_x += self._draw_tag(draw, tag_x, tag_y, tag, compact=compact)

        # Posizione Y dopo la card (l'immagine viene gestita separatamente in generate())
        return y + card_height + 40
    
    def _draw_footer(self, draw: ImageDraw, height: int):
        """Disegna il footer dell'infografica."""
        y = height - 80  # 40 * 2

        # Linea separatrice
        draw.line((80, y - 30, self.config.width - 80, y - 30),
                  fill=self._hex_to_rgb("#334155"), width=2)
        
        # Testo footer centrato
        bbox = draw.textbbox((0, 0), self.config.footer_text, font=self.font_small)
        text_width = bbox[2] - bbox[0]
        x = (self.config.width - text_width) // 2
        draw.text((x, y), self.config.footer_text, 
                  fill=self._hex_to_rgb(self.config.secondary_text), 
                  font=self.font_small)
    
    def generate(self, item: BulletinItem, output_path: Optional[str] = None) -> Image:
        """
        Genera l'infografica per un singolo bollettino di sicurezza.

        Args:
            item: BulletinItem da includere
            output_path: Path opzionale per salvare l'immagine

        Returns:
            Oggetto PIL.Image dell'infografica generata
        """
        card_width = self.config.width - 160
        footer_height = 120
        
        # Usa sempre l'altezza fissa dal config
        current_height = self.config.height

        # Crea immagine con dimensioni fisse
        image = Image.new('RGB', (self.config.width, current_height),
                          self._hex_to_rgb(self.config.background_color))
        draw = ImageDraw.Draw(image)

        # Header
        y_offset = self._draw_header(draw, image)

        # Card singola a larghezza piena
        card_x = 80
        
        # Calcola spazio disponibile per la card (dal header al footer)
        available_height = current_height - y_offset - footer_height - 40  # 40 = margine
        
        # Carica immagine allegata se presente
        attached_img = None
        attached_img_size = (0, 0)
        
        if item.image_path and os.path.exists(item.image_path):
            try:
                attached_img = Image.open(item.image_path)
                attached_img = attached_img.convert("RGBA")
                
                # Calcola lo spazio disponibile per l'immagine
                # L'immagine va sotto la card, quindi calcoliamo quanto spazio abbiamo
                # Stimiamo l'altezza minima della card (senza espansione)
                min_card_height = 450  # Altezza minima stimata per la card
                space_for_image = available_height - min_card_height - 40  # 40 = margine tra card e immagine
                
                if space_for_image > 100:  # Solo se c'è abbastanza spazio
                    max_img_width = card_width - 80
                    max_img_height = min(space_for_image, 600)  # Max 600px o lo spazio disponibile
                    
                    img_ratio = attached_img.width / attached_img.height
                    new_width = min(attached_img.width, max_img_width)
                    new_height = int(new_width / img_ratio)
                    
                    if new_height > max_img_height:
                        new_height = max_img_height
                        new_width = int(new_height * img_ratio)
                    
                    attached_img = attached_img.resize((new_width, new_height), Image.LANCZOS)
                    attached_img_size = (new_width, new_height)
                else:
                    # Non c'è spazio sufficiente, ignora l'immagine
                    print(f"⚠️  Spazio insufficiente per l'immagine, verrà omessa")
                    attached_img = None
                    
            except Exception as e:
                print(f"⚠️  Errore caricamento immagine {item.image_path}: {e}")
                attached_img = None

        # Calcola altezza della card
        if attached_img:
            # Con immagine: la card è compatta, l'immagine va sotto
            card_height = available_height - attached_img_size[1] - 40  # 40 = spazio tra card e immagine
            card_min_height = card_height
            compact_mode = True
        else:
            # Senza immagine: la card riempie tutto lo spazio disponibile
            card_min_height = available_height
            compact_mode = False

        # Disegna la card
        card_end_y = self._draw_item_card(draw, image, card_x, y_offset, item, card_width, card_min_height, compact=compact_mode)

        # Posiziona immagine sotto la card
        if attached_img:
            img_y = card_end_y  # Subito sotto la card
            img_x = card_x + (card_width - attached_img_size[0]) // 2  # Centrata
            
            if attached_img.mode == 'RGBA':
                image.paste(attached_img, (img_x, img_y), attached_img)
            else:
                image.paste(attached_img, (img_x, img_y))

        # Footer
        self._draw_footer(draw, current_height)

        # Salva se richiesto
        if output_path:
            image.save(output_path, quality=95)
            print(f"✅ Infografica salvata in: {output_path}")

        return image
    
    def generate_from_dict(self, data: dict, output_path: Optional[str] = None) -> Image:
        """
        Genera infografica da un singolo dizionario.

        Formato dict:
        {
            "category": "aggiornamenti" | "vulnerabilita" | "patch" | "advisory" | "incident",
            "severity": "critical" | "high" | "medium" | "low" | "info",
            "product": "Nome Prodotto",
            "description": "Descrizione breve",
            "tags": ["tag1", "tag2"],  # opzionale
            "cve_id": "CVE-2024-1234",  # opzionale
            "version": "1.0.0",  # opzionale
            "image": "path/to/image.png"  # opzionale - immagine da mostrare sotto la card
        }
        """
        category_map = {c.value[0]: c for c in Category}
        severity_map = {s.value[0]: s for s in Severity}

        item = BulletinItem(
            category=category_map.get(data["category"].lower(), Category.ADVISORY),
            severity=severity_map.get(data["severity"].lower(), Severity.MEDIUM),
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

    # Banner
    print("\n" + "=" * 60)
    print("  🔒 AlertForge v1.0")
    print("=" * 60)

    # Carica configurazione
    config = None
    config_file = args.config
    
    # Se non specificato, cerca config.json di default
    if not config_file and os.path.exists("config.json"):
        config_file = "config.json"
    
    if config_file:
        print(f"\n📋 Caricamento configurazione da: {config_file}")
        config, error = load_config_from_file(config_file)
        if error:
            print(f"❌ Errore: {error}")
            sys.exit(1)
        print("✅ Configurazione caricata")
    else:
        # Configurazione di default con data corrente
        config = BulletinConfig(date=datetime.now().strftime("%d/%m/%Y"))

    # Modalità batch
    if args.batch:
        print(f"\n🔄 Modalità BATCH attivata")
        print(f"📂 Input directory: {args.batch}")
        print(f"📂 Output directory: {args.output_dir}")

        successes, failures, errors = process_batch(args.batch, args.output_dir, config)

        print("\n" + "=" * 60)
        print(f"✅ Completati con successo: {successes}")
        print(f"❌ Falliti: {failures}")

        if failures > 0 and args.verbose:
            print("\n⚠️  Errori:")
            for error in errors:
                print(f"  - {error}")

        print("=" * 60 + "\n")
        sys.exit(0 if failures == 0 else 1)

    # Modalità singolo file
    input_file = args.input
    
    # Se non specificato, cerca bulletins.json di default
    if not input_file and os.path.exists("bulletins.json"):
        input_file = "bulletins.json"
    
    if not input_file or not args.output:
        print("\n❌ Errore: Specificare --input e --output per modalità singolo file")
        print("          oppure --batch per modalità batch")
        if not input_file:
            print("          (bulletins.json non trovato nella directory corrente)\n")
        else:
            print()
        parser.print_help()
        sys.exit(1)

    print(f"\n📄 Input file: {input_file}")

    # Carica bollettini
    print("\n🔄 Caricamento bollettini...")
    bulletins, error = load_bulletins_from_file(input_file)
    if error:
        print(f"❌ Errore: {error}")
        sys.exit(1)

    print(f"✅ Caricati {len(bulletins)} bollettini")

    # Genera infografiche (una per bollettino)
    print("\n🎨 Generazione infografiche...")
    try:
        generator = SecurityBulletinGenerator(config)

        if len(bulletins) == 1:
            # Singolo bollettino: usa il nome output specificato
            image = generator.generate_from_dict(bulletins[0], args.output)
            print(f"✅ Infografica generata: {args.output}")
            print(f"   Dimensioni: {image.size[0]}x{image.size[1]} px")
        else:
            # Multipli bollettini: genera file numerati
            output_base, output_ext = os.path.splitext(args.output)
            if not output_ext:
                output_ext = ".png"

            for i, bulletin in enumerate(bulletins, 1):
                output_file = f"{output_base}_{i:02d}{output_ext}"
                image = generator.generate_from_dict(bulletin, output_file)
                print(f"✅ [{i}/{len(bulletins)}] {output_file} ({image.size[0]}x{image.size[1]} px)")

            print(f"\n📊 Generate {len(bulletins)} infografiche")

        print("\n" + "=" * 60 + "\n")
    except Exception as e:
        print(f"❌ Errore durante la generazione: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()