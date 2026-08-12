/**
 * The 256 words a fingerprint is spoken in. Byte value N maps to WORDLIST[N].
 *
 * Authored for this project subject to three constraints, all enforced by
 * fingerprint.test.ts:
 *
 *   - 4 to 7 letters, lowercase ASCII
 *   - no two words share a 3-letter prefix
 *   - no two words are within a Levenshtein distance of 1
 *
 * The last two are the point. A fingerprint is read aloud over a voice call to
 * confirm a peer's key, so a misheard or mistyped word must fail to match
 * anything rather than quietly matching a neighbour.
 *
 * This list is part of the user-facing contract: reordering it changes every
 * fingerprint ever displayed, and a known-answer test pins it.
 */
export const WORDLIST: readonly string[] = [
  "acorn", "agent", "alert", "alpha", "angle", "apple", "armor", "aspen",
  "audio", "award", "badge", "bamboo", "basil", "birch", "black", "bloom",
  "bone", "bottle", "brain", "bronze", "bucket", "bugle", "bundle", "button",
  "cactus", "captain", "cedar", "census", "chicken", "cigar", "citrus", "clever",
  "club", "cocoa", "colony", "coral", "cover", "crab", "crop", "cube",
  "custom", "daisy", "dawn", "decade", "delta", "desert", "diamond", "dinner",
  "diver", "dodge", "donkey", "double", "dress", "dryer", "dusk", "dynamo",
  "easel", "edge", "eight", "elegant", "emerald", "engine", "entry", "escape",
  "ethics", "exact", "expert", "fabric", "falcon", "farm", "fault", "fern",
  "fiction", "figure", "first", "fleet", "fluid", "foil", "fossil", "freedom",
  "fruit", "future", "game", "gear", "ghost", "ginger", "glide", "goal",
  "gospel", "grace", "grocery", "guitar", "gutter", "half", "happy", "haven",
  "head", "hidden", "hint", "hobby", "honey", "hotel", "hundred", "icon",
  "igloo", "inch", "insect", "ivory", "jaguar", "jelly", "journal", "july",
  "justice", "keen", "kick", "kiosk", "knife", "label", "lake", "large",
  "lava", "legacy", "leopard", "level", "life", "lion", "little", "load",
  "logic", "lotus", "lower", "lunar", "machine", "major", "marble", "meadow",
  "member", "message", "mild", "mission", "monarch", "mosaic", "movie", "muscle",
  "napkin", "neat", "neon", "network", "noble", "normal", "nurse", "oasis",
  "ocean", "often", "onion", "orange", "organ", "outdoor", "oxygen", "paddle",
  "palace", "parade", "pause", "pencil", "perfect", "phone", "picture", "pillar",
  "pistol", "plain", "plug", "polar", "popcorn", "powder", "price", "public",
  "pump", "purple", "quail", "quota", "radar", "ranch", "razor", "recipe",
  "region", "rent", "return", "ribbon", "rifle", "risk", "robin", "roll",
  "rough", "ruler", "rural", "safari", "satin", "scene", "scooter", "second",
  "senate", "shade", "shock", "siege", "single", "site", "skill", "slope",
  "smoke", "soap", "soft", "soul", "sphere", "spoon", "stadium", "stone",
  "style", "summer", "surf", "sweater", "symbol", "tackle", "tank", "tavern",
  "tech", "tennis", "theater", "thread", "tiger", "title", "tomato", "topic",
  "track", "trophy", "tuna", "twin", "uniform", "urban", "useful", "vacuum",
  "vapor", "velvet", "vessel", "view", "violet", "vital", "volcano", "waist",
  "warn", "wave", "whale", "width", "wisdom", "work", "yacht", "yoga",
];
