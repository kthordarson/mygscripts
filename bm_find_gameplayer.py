#Find all uses of GamePlayer type + the g_currentRemotePlayer global
#@category BM
prog = currentProgram
fm = prog.getFunctionManager()
st = prog.getSymbolTable()
dtm = prog.getDataTypeManager()
rep = []

def base_name(dt):
    n = dt.getName()
    return n.replace(" *","").replace("*","").strip()

# 1) functions whose return/params/locals reference GamePlayer
hits = []
for f in fm.getFunctions(True):
    where = []
    try:
        if "GamePlayer" in f.getReturnType().getName(): where.append("ret")
        for p in f.getParameters():
            if "GamePlayer" in p.getDataType().getName(): where.append("param:%s" % p.getName())
        for v in f.getLocalVariables():
            if "GamePlayer" in v.getDataType().getName(): where.append("loc:%s" % v.getName())
    except: pass
    if where:
        hits.append("%s @ %s : %s" % (f.getName(), f.getEntryPoint(), ", ".join(where))
)
rep.append("=== FUNCTIONS using GamePlayer (%d) ===" % len(hits))
rep.extend(hits[:60])

# 2) data symbols typed GamePlayer
dcount = 0
for d in prog.getListing().getDefinedData(True):
    try:
        if "GamePlayer" in d.getDataType().getName():
            rep.append("DATA %s %s @ %s" % (d.getDataType().getName(), d.getLabel(), d.getAddress()))
            dcount += 1
    except: pass
rep.append("=== DATA typed GamePlayer: %d ===" % dcount)

# 3) the g_currentRemotePlayer global: type + value
for nm in ["g_currentRemotePlayer"]:
    syms = st.getGlobalSymbols(nm)
    for s in syms:
        a = s.getAddress()
        d = getDataAt(a)
        rep.append("GLOBAL %s @ %s type=%s" % (nm, a, (d.getDataType().getName() if d else "<undef>")))

# 4) GamePlayer struct current definition
lst = []
from java.util import ArrayList
al = ArrayList(); dtm.findDataTypes("GamePlayer", al)
if al.size() > 0:
    gp = al.get(0)
    rep.append("=== GamePlayer size=0x%x cat=%s ===" % (gp.getLength(), gp.getCategoryPath()))

print("\n".join(rep))
