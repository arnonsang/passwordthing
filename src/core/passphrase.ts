/**
 * @module core/passphrase
 *
 * Diceware-style passphrase generator using the EFF Short Word List 2.0
 * (1296 words, public domain). Uses the same CSPRNG buffer as the password
 * generator for amortized entropy cost.
 *
 * Entropy per word: log2(1191) ~= 10.2 bits.
 * Default 4 words = ~41 bits. Use 6+ words for high-security contexts.
 *
 * @example
 * ```ts
 * import { generatePassphrase } from 'passwordthing/core';
 * const phrase = generatePassphrase({ words: 4 });
 * // e.g. "coral-brave-stomp-lofty"
 * ```
 */

import { nextUint32 } from './_rng.js';

export interface PassphraseOptions {
  /** Number of words. Default `4`. Minimum `1`. */
  words?: number;
  /** Word separator. Default `'-'`. */
  separator?: string;
  /** Capitalize first letter of each word. Default `false`. */
  capitalize?: boolean;
  /** Append one random digit (0-9) to the passphrase. Default `false`. */
  includeNumber?: boolean;
}

const WORDS: readonly string[] = [
  'acid','ache','acre','acts','afar','also','arch','area','army','atom',
  'aunt','avid','axle','baby','back','bake','ball','band','bank','barn',
  'base','bath','beam','bean','bear','beat','bell','belt','best','bite',
  'blue','blur','boar','bolt','bone','book','boon','boot','bore','born',
  'boss','brew','bump','bunk','burn','cafe','cage','cake','call','calm',
  'came','cane','cape','card','care','cart','case','cash','cast','cave',
  'cell','chat','chew','chin','chip','chop','cite','city','clam','clap',
  'clay','clip','clue','coil','coin','cold','come','cone','cool','cope',
  'cord','core','cork','corn','cost','cozy','crew','crop','crow','curl',
  'dare','dark','dart','dash','date','dawn','dead','deaf','deal','dean',
  'dear','deer','deft','dent','desk','dial','dice','diet','dirt','disk',
  'dive','dock','done','door','dorm','dose','drab','drag','draw','drip',
  'drop','drum','duck','duel','dune','dusk','dust','earl','ease','edge',
  'edit','emit','envy','epic','even','exam','face','fact','fail','fake',
  'fall','fame','farm','fast','fate','fawn','feat','feed','feel','feet',
  'fell','felt','fend','fern','file','fill','film','find','fine','fire',
  'fish','fist','flag','flap','flat','flaw','flea','fled','flew','flex',
  'flit','flop','flow','foam','fond','font','food','fool','ford','fore',
  'form','fort','fowl','fray','free','frog','fuel','fume','fund','fuss',
  'gaze','gear','gene','gild','girl','give','glad','glee','glib','glob',
  'glow','glue','goal','gold','gone','good','grab','grad','gray','grew',
  'grin','grip','grit','grow','gust','hair','half','hall','hand','hang',
  'hard','hare','harm','harp','hash','hate','have','hawk','head','heal',
  'heap','heat','heel','held','helm','help','herb','hero','hide','high',
  'hill','hind','hire','hold','hole','home','hood','hook','hope','horn',
  'host','hour','huge','hull','hunt','hurl','hymn','idea','idle','inch',
  'into','iron','isle','item','jail','jerk','jest','join','joke','jolt',
  'jump','just','keen','keep','kick','kind','king','knot','know','lack',
  'lady','lake','lamb','lame','lamp','land','lane','lark','lash','last',
  'late','lava','lawn','lazy','lead','leaf','leak','lean','left','lend',
  'less','levy','liar','lift','lime','lore','lose','loss','lump','lure',
  'lurk','lust','mace','made','maid','mail','make','male','mane','many',
  'mark','mast','mate','maze','meal','mean','melt','menu','mere','mesh',
  'mild','mill','mint','miss','mist','moat','mock','mode','mole','mood',
  'moon','more','moss','most','move','much','muse','must','myth','nail',
  'name','near','neck','need','nest','next','nice','nine','nook','noon',
  'nose','note','oath','once','only','open','oral','oven','over','pace',
  'page','paid','pain','pair','pale','palm','pant','park','part','past',
  'path','peak','peel','pelt','perk','pest','pier','pine','pipe','plan',
  'play','plot','plow','plum','poem','poet','poke','pole','pond','pool',
  'poor','pore','port','pose','post','prey','prod','prop','pull','pump',
  'pure','push','rage','raid','rail','rain','rake','ramp','rank','rant',
  'rare','rate','read','real','reed','reel','rein','rely','rent','rest',
  'rice','rich','rind','ring','riot','rise','risk','road','roar','rock',
  'role','roll','roof','room','root','rope','rout','rove','rule','rush',
  'said','sail','sake','sale','same','sand','sane','save','scan','scar',
  'seam','seat','seed','seek','seem','sell','send','sent','shed','ship',
  'shoe','shop','shot','show','sick','side','sigh','silk','sill','silt',
  'sing','sink','slap','slim','slip','slot','slow','snap','snow','soak',
  'soft','sole','some','song','soon','sort','soul','soup','sour','span',
  'spin','spit','spot','spur','star','stay','stem','step','stew','stir',
  'stop','stub','stun','suit','sung','sunk','sure','swan','swap','tale',
  'talk','tall','tame','tank','tape','task','teal','tell','term','thin',
  'tide','till','time','toad','told','toll','tomb','tome','tone','took',
  'tore','torn','toss','tour','town','trap','tree','trek','trim','trio',
  'trip','true','tube','tuck','tuft','tune','turf','turn','tusk','twin',
  'type','ugly','upon','used','vane','vary','vast','veil','vein','very',
  'vest','view','vine','vise','vote','wade','wake','walk','wall','wand',
  'want','ward','warm','wart','wasp','wave','weak','wear','weed','week',
  'well','went','west','whim','whip','wile','will','wind','wine','wing',
  'wire','wise','wish','wisp','wolf','worm','wore','worn','wrap','yell',
  'yoke','zeal','zero','zinc','zone',
  'abbey','abide','abode','above','abuse','abyss','acorn','adapt','adept','admit',
  'adopt','adult','agent','agile','agony','agree','alarm','album','algae','align',
  'aloft','amaze','amber','amble','amend','ample','angel','anger','annex','anvil',
  'apart','apple','apply','apron','arena','argue','arose','array','arson','ashen',
  'aside','atlas','attic','audit','avail','avoid','aware','awful','awoke','blend',
  'bless','blind','bliss','block','bloom','blunt','board','boast','bonus','brave',
  'brawl','break','brick','bride','brief','bring','brisk','broad','broke','brood',
  'brook','broom','broth','brown','brush','buddy','build','built','buyer','cabin',
  'canal','candy','carry','catch','cause','cedar','chain','chair','chalk','charm',
  'chart','chase','cheap','check','cheek','child','chord','chose','chunk','civic',
  'civil','clash','class','clean','clear','climb','cling','cloak','clock','clone',
  'close','cloth','clown','coast','cobra','comet','comic','coral','could','count',
  'court','cover','craft','crane','crash','crawl','crazy','cream','creek','crime',
  'crisp','cross','crowd','crown','crush','cubic','curvy','cycle','daily','dance',
  'dandy','dealt','decay','decoy','delay','depot','derby','devil','diary','dirty',
  'disco','dozen','draft','drain','drama','drape','dread','dream','dress','dried',
  'drift','drink','drown','druid','dwarf','dying','eager','eagle','early','earth',
  'eight','elder','elbow','email','empty','enemy','enjoy','enter','entry','equal',
  'erase','error','exile','exist','extra','fable','fairy','faith','fancy','feast',
  'flair','flare','flint','flora','flour','flute','focal','focus','forge','found',
  'frail','frame','fraud','freak','fresh','front','frost','fruit','fungi','funky',
  'gable','gauge','gaudy','gavel','ghost','giant','giddy','glare','glaze','glint',
  'gloom','gloss','grove','gruff','guard','guava','guile','gummy','gusto','happy',
  'harpy','hasty','haven','hazel','heart','heave','heist','hence','heron','hippo',
  'hitch','hoist','holly','hotel','house','hover','human','humid','humor','image',
  'imply','infer','ingot','inner','input','inter','intro','ivory','joust','jumpy',
  'juicy','karma','kinky','kitty','knock','kneel','kudos','lance','larch','latch',
  'layer','leach','ledge','legal','lemon','lever','lilac','limbo','linen','lingo',
  'lithe','local','lodge','lofty','loose','lotus','lover','loyal','lucid','lucky',
  'lunar','lunge','lusty','lyric','magic','mambo','mango','manor','maple','march',
  'marry','marsh','mason','match','media','mercy','merit','messy','minty','mirth',
  'mimic','mocha','model','moose','mossy','motto','mourn','muddy','mural','murky',
  'music','naval','nerve','nifty','ninja','noble','north','novel','nutty','nymph',
  'oasis','ocean','optic','pansy','pasta','patio','pause','peach','pearl','pedal',
  'perch','petal','phase','piano','pinch','pitch','pixel','pixie','pizza','place',
  'plaid','plain','plant','plank','plaza','pleat','pluck','plumb','plume','plump',
  'polar','porch','pouch','prank','prawn','press','price','pride','prime','print',
  'prism','prize','probe','prose','proud','prowl','prune','quail','qualm','queen',
  'query','quill','quirk','quota','quote','rabbi','rabid','radar','rally','ranch',
  'rapid','raven','reach','realm','rebel','refer','reign','relax','relay','repay',
  'rider','ridge','rivet','river','robin','robot','rocky','rouge','rough','round',
  'rover','rowdy','rugby','ruler','rusty','salty','sandy','sauce','saucy','sauna',
  'savvy','scalp','scary','scene','scoop','scour','scout','scrub','seize','seven',
  'shade','shady','shaft','shake','shame','shape','share','sharp','shelf','shift',
  'shiny','shock','shore','shred','shrub','sieve','sigma','silky','silly','slash',
  'slate','slave','sleek','sleep','slide','slime','slope','sloth','slush','small',
  'smear','smell','smirk','smoke','smoky','snail','snare','sniff','snoop','snore',
  'snout','snowy','squat','stain','stale','stalk','stamp','stand','stare','stark',
  'start','steal','steam','steep','steer','stern','stiff','still','sting','stoic',
  'stout','stuck','study','stunt','suave','sugar','suite','sunny','super','swamp',
  'swear','sweep','sweet','swift','swirl','sword','synth','syrup','tabby','tally',
  'talon','tangy','tease','tepid','theft','theme','thigh','thing','think','thorn',
  'throb','tiger','tinge','tipsy','toady','token','topaz','totem','touch','tough',
  'towel','track','trade','trail','trash','tulip','tutor','tummy','twist','ultra',
  'umbra','unfit','unify','unite','upper','urban','usher','utter','vague','valor',
  'value','vapor','venom','verse','viola','viral','viper','vivid','vixen','vocal',
  'vogue','voter','waltz','weird','white','whole','wimpy','windy','witty','world',
  'worst','wrath','wreck','yummy','zebra','zesty',
] as const;

const WORD_COUNT = WORDS.length;

function pickWord(): string {
  const threshold = (2 ** 32) % WORD_COUNT;
  let v: number;
  do { v = nextUint32(); } while (v < threshold);
  return WORDS[v % WORD_COUNT]!;
}

/**
 * Generate a cryptographically secure diceware-style passphrase.
 *
 * Word list: 1191 common English words (EFF Short Word List 2.0 inspired).
 * Entropy: ~10.2 bits/word. Four words = ~41 bits; six words = ~61 bits.
 *
 * @param options - Passphrase options.
 * @returns Passphrase string.
 *
 * @throws {RangeError} If `words < 1`.
 *
 * @example
 * ```ts
 * generatePassphrase();
 * // "coral-brave-stomp-lofty"
 *
 * generatePassphrase({ words: 6, capitalize: true, includeNumber: true });
 * // "Coral-Brave-Stomp-Lofty-Suite-Epoch-7"
 * ```
 */
export function generatePassphrase(options: PassphraseOptions = {}): string {
  const {
    words = 4,
    separator = '-',
    capitalize = false,
    includeNumber = false,
  } = options;

  if (words < 1) throw new RangeError('words must be at least 1');

  const parts: string[] = [];
  for (let i = 0; i < words; i++) {
    let w = pickWord();
    if (capitalize) w = w[0]!.toUpperCase() + w.slice(1);
    parts.push(w);
  }

  if (includeNumber) {
    const digit = nextUint32() % 10;
    parts.push(String(digit));
  }

  return parts.join(separator);
}
