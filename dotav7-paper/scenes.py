"""
Manim scenes for the TC-HKEM (Triple-Committed Hybrid KEM) paper.
Generates both static figures (for LaTeX) and animated videos (v1→v7 evolution).
"""
from manim import *
import numpy as np

# ── Color palette ────────────────────────────────────────────────────────────
PQ_COLOR = "#6C5CE7"       # Post-quantum (ML-KEM) — purple
CLASSICAL_COLOR = "#00B894" # Classical (X25519) — green
MK_COLOR = "#E17055"        # Master key / passphrase — orange-red
DERIVED_COLOR = "#FDCB6E"   # Derived key — gold
HKDF_COLOR = "#0984E3"      # HKDF combiner — blue
COMMIT_COLOR = "#D63031"    # Commitment — red
AES_COLOR = "#00CEC9"       # AES-GCM — teal
BG_DARK = "#1A1A2E"

config.background_color = BG_DARK


class TCHKEMConstruction(Scene):
    """Figure 1: The TC-HKEM key derivation pipeline."""

    def construct(self):
        title = Text("TC-HKEM Construction", font_size=36, color=WHITE).to_edge(UP, buff=0.4)
        subtitle = Text("Triple-Committed Hybrid KEM — dota v7", font_size=20, color=GREY_B).next_to(title, DOWN, buff=0.15)
        self.add(title, subtitle)

        # ── Input boxes ──────────────────────────────────────────────────
        def make_box(label, color, width=2.0, height=0.7):
            r = RoundedRectangle(corner_radius=0.12, width=width, height=height,
                                 stroke_color=color, fill_color=color, fill_opacity=0.15, stroke_width=2)
            t = Text(label, font_size=16, color=color)
            return VGroup(r, t)

        # Top row: the three input shared secrets
        ss_kem = make_box("ss_kem", PQ_COLOR, 1.8)
        ss_dh  = make_box("ss_dh", CLASSICAL_COLOR, 1.8)
        ct_kem = make_box("ct_kem", PQ_COLOR, 1.8)
        eph_pk = make_box("eph_pk", CLASSICAL_COLOR, 1.8)

        top_row = VGroup(ss_kem, ss_dh, ct_kem, eph_pk).arrange(RIGHT, buff=0.35)
        top_row.move_to(UP * 1.2)
        self.add(top_row)

        # Labels above
        for box, lbl in [(ss_kem, "ML-KEM-768\nshared secret"),
                          (ss_dh,  "X25519\nshared secret"),
                          (ct_kem, "KEM\nciphertext"),
                          (eph_pk, "Ephemeral\npublic key")]:
            t = Text(lbl, font_size=11, color=GREY_B).next_to(box, UP, buff=0.12)
            self.add(t)

        # ── HMAC commitment box ──────────────────────────────────────────
        mk_box = make_box("mk", MK_COLOR, 1.3, 0.6)
        mk_box.move_to(RIGHT * 4.2 + DOWN * 0.3)
        mk_label = Text("Argon2id\nmaster key", font_size=11, color=GREY_B).next_to(mk_box, UP, buff=0.1)

        hmac_box = RoundedRectangle(corner_radius=0.12, width=3.2, height=0.7,
                                     stroke_color=COMMIT_COLOR, fill_color=COMMIT_COLOR,
                                     fill_opacity=0.12, stroke_width=2)
        hmac_text = MathTex(r"\tau = \text{HMAC}(mk,\; ct \| eph)", font_size=24, color=COMMIT_COLOR)
        hmac_group = VGroup(hmac_box, hmac_text)
        hmac_group.move_to(RIGHT * 1.5 + DOWN * 0.3)

        self.add(mk_box, mk_label, hmac_group)

        # Arrows from ct_kem and eph_pk to HMAC
        arr1 = Arrow(ct_kem.get_bottom(), hmac_group.get_top(), buff=0.1,
                      stroke_width=1.5, color=PQ_COLOR, max_tip_length_to_length_ratio=0.15)
        arr2 = Arrow(eph_pk.get_bottom(), hmac_group.get_top(), buff=0.1,
                      stroke_width=1.5, color=CLASSICAL_COLOR, max_tip_length_to_length_ratio=0.15)
        arr3 = Arrow(mk_box.get_left(), hmac_group.get_right(), buff=0.1,
                      stroke_width=1.5, color=MK_COLOR, max_tip_length_to_length_ratio=0.15)
        self.add(arr1, arr2, arr3)

        # ── Concatenation bar ────────────────────────────────────────────
        concat_rect = RoundedRectangle(corner_radius=0.08, width=9.5, height=0.6,
                                        stroke_color=GREY_A, fill_color=WHITE,
                                        fill_opacity=0.05, stroke_width=1.5)
        concat_rect.move_to(DOWN * 1.5)

        parts = [
            ("ss_{kem}", PQ_COLOR, "32B"),
            ("ss_{dh}", CLASSICAL_COLOR, "32B"),
            ("ct_{kem}", PQ_COLOR, "1088B"),
            ("eph_{pk}", CLASSICAL_COLOR, "32B"),
            (r"\tau", COMMIT_COLOR, "32B"),
        ]

        ikm_pieces = VGroup()
        for i, (sym, col, sz) in enumerate(parts):
            piece = VGroup(
                Rectangle(width=1.5 if sym != "ct_{kem}" else 2.2, height=0.45,
                          stroke_color=col, fill_color=col, fill_opacity=0.2, stroke_width=1.5),
                MathTex(sym, font_size=18, color=col),
                Text(sz, font_size=10, color=GREY_B).shift(DOWN * 0.25)
            )
            ikm_pieces.add(piece)

        ikm_pieces.arrange(RIGHT, buff=0.08)
        ikm_pieces.move_to(concat_rect.get_center())
        ikm_label = Text("IKM (1216 bytes)", font_size=13, color=GREY_A).next_to(concat_rect, LEFT, buff=0.15)
        self.add(concat_rect, ikm_pieces, ikm_label)

        # Arrows from top row and HMAC to concat bar
        for box in [ss_kem, ss_dh]:
            a = Arrow(box.get_bottom(), concat_rect.get_top(), buff=0.08,
                      stroke_width=1.2, color=GREY_B, max_tip_length_to_length_ratio=0.1)
            self.add(a)
        arr_tau = Arrow(hmac_group.get_bottom(), concat_rect.get_top() + RIGHT * 2,
                        buff=0.08, stroke_width=1.5, color=COMMIT_COLOR,
                        max_tip_length_to_length_ratio=0.12)
        self.add(arr_tau)

        # ── HKDF box ────────────────────────────────────────────────────
        hkdf_box = RoundedRectangle(corner_radius=0.12, width=4.5, height=0.7,
                                     stroke_color=HKDF_COLOR, fill_color=HKDF_COLOR,
                                     fill_opacity=0.15, stroke_width=2.5)
        hkdf_text = MathTex(r"K = \text{HKDF-SHA256}(\text{salt}, \text{IKM}, \text{info})",
                            font_size=22, color=HKDF_COLOR)
        hkdf_group = VGroup(hkdf_box, hkdf_text)
        hkdf_group.move_to(DOWN * 2.7)
        self.add(hkdf_group)

        arr_ikm = Arrow(concat_rect.get_bottom(), hkdf_group.get_top(), buff=0.08,
                         stroke_width=2, color=GREY_A, max_tip_length_to_length_ratio=0.1)
        self.add(arr_ikm)

        # ── Output AES key ──────────────────────────────────────────────
        aes_box = make_box("AES-256 Key", AES_COLOR, 2.5, 0.6)
        aes_box.move_to(DOWN * 3.7)
        aes_label = Text("Per-secret encryption key (256 bits)", font_size=12, color=GREY_B).next_to(aes_box, DOWN, buff=0.1)
        self.add(aes_box, aes_label)

        arr_out = Arrow(hkdf_group.get_bottom(), aes_box.get_top(), buff=0.08,
                         stroke_width=2.5, color=DERIVED_COLOR, max_tip_length_to_length_ratio=0.1)
        self.add(arr_out)

        self.wait(0.1)


class GameHopping(Scene):
    """Figure 2: The 4-game security proof for TC-HKEM."""

    def construct(self):
        title = Text("TC-HKEM Security Proof — Game Sequence", font_size=32, color=WHITE).to_edge(UP, buff=0.4)
        self.add(title)

        games = [
            ("Game 0", "Real IND-CCA", "Challenge uses real\nTC-HKEM combiner", WHITE),
            ("Game 1", "RO model", r"Replace KDF with" + "\nrandom oracle H", GREY_B),
            ("Game 2", "ML-KEM hop", "Replace ss*_kem\nwith random", PQ_COLOR),
            ("Game 3", "X25519 hop", "Replace ss*_dh\nwith random", CLASSICAL_COLOR),
            ("Game 4", "Random key", "K* indistinguishable\nfrom random", DERIVED_COLOR),
        ]

        game_groups = VGroup()
        for i, (name, subtitle, desc, color) in enumerate(games):
            box = RoundedRectangle(corner_radius=0.15, width=2.2, height=2.4,
                                   stroke_color=color, fill_color=color,
                                   fill_opacity=0.08, stroke_width=2)
            name_t = Text(name, font_size=18, color=color, weight=BOLD)
            sub_t = Text(subtitle, font_size=12, color=GREY_A)
            desc_t = Text(desc, font_size=11, color=GREY_B, line_spacing=0.8)
            inner = VGroup(name_t, sub_t, desc_t).arrange(DOWN, buff=0.2)
            inner.move_to(box.get_center())
            game_groups.add(VGroup(box, inner))

        game_groups.arrange(RIGHT, buff=0.25)
        game_groups.move_to(UP * 0.0)
        self.add(game_groups)

        # Transition arrows with advantage bounds
        bounds = [
            r"|G_0 - G_1| = 0",
            r"|G_1 - G_2| \leq \text{Adv}^{\text{cca}}_{\text{KEM}}",
            r"|G_2 - G_3| \leq \text{Adv}^{\text{cdh}}_{\text{X25519}}",
            r"|G_3 - \tfrac{1}{2}| \leq \frac{q_H}{2^{256}}",
        ]

        for i in range(4):
            g1 = game_groups[i]
            g2 = game_groups[i + 1]
            mid = (g1.get_right() + g2.get_left()) / 2
            arr = Arrow(g1.get_right(), g2.get_left(), buff=0.05,
                        stroke_width=1.5, color=GREY_A, max_tip_length_to_length_ratio=0.15)
            bound_tex = MathTex(bounds[i], font_size=14, color=GREY_B)
            bound_tex.next_to(arr, UP, buff=0.08)
            self.add(arr, bound_tex)

        # Bottom: final bound
        final = MathTex(
            r"\text{Adv}^{\text{ind-cca}}_{\text{TC-HKEM}}(\mathcal{A}) \leq "
            r"\text{Adv}^{\text{cca}}_{\text{ML-KEM}}(\mathcal{B}_1) + "
            r"\text{Adv}^{\text{cdh}}_{\text{X25519}}(\mathcal{B}_2) + "
            r"\frac{q_H}{2^{256}}",
            font_size=22, color=DERIVED_COLOR
        )
        final.to_edge(DOWN, buff=0.6)

        final_box = SurroundingRectangle(final, buff=0.15, corner_radius=0.1,
                                          stroke_color=DERIVED_COLOR, fill_color=DERIVED_COLOR,
                                          fill_opacity=0.05, stroke_width=1.5)
        thm = Text("Theorem 1 — Best-of-Both-Worlds", font_size=14, color=DERIVED_COLOR)
        thm.next_to(final_box, UP, buff=0.1)
        self.add(final_box, final, thm)
        self.wait(0.1)


class VersionEvolution(Scene):
    """Animated scene: v1 → v7 vault evolution."""

    def construct(self):
        title = Text("dota Vault Evolution: v1 → v7", font_size=34, color=WHITE).to_edge(UP, buff=0.3)
        self.play(Write(title), run_time=1)

        versions = [
            ("v1", "X25519-only", ["X25519 DH", "AES (mk direct)"], "#636E72"),
            ("v2", "+ Hybrid KEM", ["+ ML-KEM-768", "Flat layout"], PQ_COLOR),
            ("v3", "Nested structs", ["KemKeyPair", "X25519KeyPair"], "#636E72"),
            ("v4", "Key separation", ["+ HKDF wrapping", "Purpose labels"], HKDF_COLOR),
            ("v5", "Key commitment", ["+ HMAC commitment", "Anti-rollback"], COMMIT_COLOR),
            ("v6", "FIPS 203 ML-KEM", ["Real ML-KEM-768", "Suite metadata"], PQ_COLOR),
            ("v7", "TC-HKEM", ["+ Ciphertext binding", "+ mk commitment"], DERIVED_COLOR),
        ]

        # Build the stack from bottom up
        stack = VGroup()
        for i, (ver, desc, features, color) in enumerate(versions):
            layer_w = 8.5 - i * 0.3
            layer = RoundedRectangle(
                corner_radius=0.1, width=layer_w, height=0.8,
                stroke_color=color, fill_color=color,
                fill_opacity=0.15 + i * 0.03, stroke_width=2
            )
            ver_text = Text(ver, font_size=20, color=color, weight=BOLD)
            desc_text = Text(desc, font_size=14, color=WHITE)
            feat_text = Text(" · ".join(features), font_size=11, color=GREY_B)
            content = VGroup(ver_text, desc_text, feat_text).arrange(RIGHT, buff=0.5)
            content.move_to(layer.get_center())
            stack.add(VGroup(layer, content))

        stack.arrange(UP, buff=0.08)
        stack.move_to(DOWN * 0.3)

        # Animate each layer appearing
        for i, layer_group in enumerate(stack):
            if i == 0:
                self.play(FadeIn(layer_group, shift=UP * 0.3), run_time=0.7)
            else:
                self.play(FadeIn(layer_group, shift=UP * 0.3), run_time=0.5)
            self.wait(0.3)

        # Highlight v7 at the end
        v7_highlight = SurroundingRectangle(
            stack[-1], buff=0.08, corner_radius=0.12,
            stroke_color=DERIVED_COLOR, stroke_width=3
        )
        v7_label = Text("← TC-HKEM: Best-of-both-worlds IND-CCA + passphrase binding",
                         font_size=14, color=DERIVED_COLOR)
        v7_label.next_to(v7_highlight, RIGHT, buff=0.15)

        self.play(Create(v7_highlight), Write(v7_label), run_time=1)
        self.wait(1.5)


class PassphraseBinding(Scene):
    """Figure 3: Theorem 2 — Passphrase binding property."""

    def construct(self):
        title = Text("Theorem 2: Passphrase Binding", font_size=32, color=WHITE).to_edge(UP, buff=0.4)
        subtitle = Text("Knowledge of (dk, sk_dh) alone is insufficient without mk",
                         font_size=18, color=GREY_B).next_to(title, DOWN, buff=0.15)
        self.add(title, subtitle)

        # Left: attacker has
        attacker_title = Text("Attacker knows:", font_size=18, color=COMMIT_COLOR).move_to(LEFT * 3.5 + UP * 1.2)
        has_items = VGroup(
            Text("✓  dk (ML-KEM private key)", font_size=14, color=PQ_COLOR),
            Text("✓  sk_dh (X25519 private key)", font_size=14, color=CLASSICAL_COLOR),
            Text("✓  ek, pk_dh (public keys)", font_size=14, color=GREY_B),
            Text("✗  mk (master key)", font_size=14, color=COMMIT_COLOR),
        ).arrange(DOWN, buff=0.15, aligned_edge=LEFT).next_to(attacker_title, DOWN, buff=0.2)
        self.add(attacker_title, has_items)

        # Right: proof sketch
        proof_title = Text("Proof (2 games):", font_size=18, color=DERIVED_COLOR).move_to(RIGHT * 2.5 + UP * 1.2)

        game0 = VGroup(
            Text("Game 0:", font_size=14, color=WHITE, weight=BOLD),
            Text("τ* = HMAC(mk, ct* ‖ eph*)", font_size=13, color=GREY_B),
            Text("Only unknown in IKM", font_size=12, color=GREY_C),
        ).arrange(DOWN, buff=0.08, aligned_edge=LEFT)

        game1 = VGroup(
            Text("Game 1:", font_size=14, color=WHITE, weight=BOLD),
            Text("Replace HMAC(mk,·) with R(·)", font_size=13, color=GREY_B),
            MathTex(r"|\Pr[G_0] - \Pr[G_1]| \leq \text{Adv}^{\text{prf}}_{\text{HMAC}}",
                    font_size=16, color=MK_COLOR),
        ).arrange(DOWN, buff=0.08, aligned_edge=LEFT)

        game2 = VGroup(
            Text("Game 2:", font_size=14, color=WHITE, weight=BOLD),
            Text("τ* = R(ct* ‖ eph*) is uniform", font_size=13, color=GREY_B),
            MathTex(r"K^* \text{ indistinguishable from random}",
                    font_size=16, color=DERIVED_COLOR),
        ).arrange(DOWN, buff=0.08, aligned_edge=LEFT)

        proof_games = VGroup(game0, game1, game2).arrange(DOWN, buff=0.3, aligned_edge=LEFT)
        proof_games.next_to(proof_title, DOWN, buff=0.2)
        self.add(proof_title, proof_games)

        # Final bound
        bound = MathTex(
            r"\text{Adv}^{\text{mk-bind}}(\mathcal{A}') \leq "
            r"\text{Adv}^{\text{prf}}_{\text{HMAC}}(\mathcal{B}_3) + \frac{q_H}{2^{256}}",
            font_size=24, color=DERIVED_COLOR
        ).to_edge(DOWN, buff=0.5)
        bound_box = SurroundingRectangle(bound, buff=0.12, corner_radius=0.1,
                                          stroke_color=DERIVED_COLOR, fill_opacity=0.05,
                                          fill_color=DERIVED_COLOR, stroke_width=1.5)
        self.add(bound_box, bound)
        self.wait(0.1)


class CombinerComparison(Scene):
    """Figure 4: v6 vs v7 combiner comparison."""

    def construct(self):
        title = Text("Combiner Comparison: v6 vs v7", font_size=32, color=WHITE).to_edge(UP, buff=0.4)
        self.add(title)

        def make_combiner(label, ikm_parts, color, security_label):
            header = Text(label, font_size=20, color=color, weight=BOLD)
            parts = VGroup()
            for pname, pcol in ikm_parts:
                p = VGroup(
                    RoundedRectangle(corner_radius=0.06, width=1.4, height=0.5,
                                     stroke_color=pcol, fill_color=pcol,
                                     fill_opacity=0.2, stroke_width=1.5),
                    MathTex(pname, font_size=16, color=pcol)
                )
                parts.add(p)
            parts.arrange(RIGHT, buff=0.06)
            sec = Text(security_label, font_size=13, color=GREY_B)
            return VGroup(header, parts, sec).arrange(DOWN, buff=0.2)

        v6 = make_combiner(
            "v6 Combiner (64-byte IKM)",
            [("ss_{kem}", PQ_COLOR), ("ss_{dh}", CLASSICAL_COLOR)],
            GREY_A,
            "⚠ Worst-of-both-worlds\n(both must hold)"
        )

        v7 = make_combiner(
            "v7 TC-HKEM (1216-byte IKM)",
            [("ss_{kem}", PQ_COLOR), ("ss_{dh}", CLASSICAL_COLOR),
             ("ct_{kem}", PQ_COLOR), ("eph_{pk}", CLASSICAL_COLOR),
             (r"\tau", COMMIT_COLOR)],
            DERIVED_COLOR,
            "✓ Best-of-both-worlds\n+ passphrase binding"
        )

        comparison = VGroup(v6, v7).arrange(DOWN, buff=0.8)
        comparison.move_to(ORIGIN)
        self.add(comparison)

        # Arrow between
        upgrade_arrow = Arrow(v6.get_bottom(), v7.get_top(), buff=0.15,
                               stroke_width=2.5, color=DERIVED_COLOR,
                               max_tip_length_to_length_ratio=0.1)
        upgrade_text = Text("GHP18 ciphertext binding\n+ HMAC(mk) commitment",
                            font_size=13, color=DERIVED_COLOR)
        upgrade_text.next_to(upgrade_arrow, RIGHT, buff=0.2)
        self.add(upgrade_arrow, upgrade_text)
        self.wait(0.1)
