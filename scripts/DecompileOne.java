import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.util.task.ConsoleTaskMonitor;
import java.io.FileWriter;

public class DecompileOne extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new Exception("Usage: DecompileOne <function_name> <output_path>");
        }
        String targetName = args[0];
        String outPath = args[1];

        FunctionManager funcMgr = currentProgram.getFunctionManager();
        Function target = null;
        for (Function func : funcMgr.getFunctions(true)) {
            if (func.getName().equals(targetName)) {
                target = func;
                break;
            }
        }

        String json;
        if (target == null) {
            json = "{\"error\":\"function not found: " + escape(targetName) + "\"}";
        } else {
            DecompInterface decompiler = new DecompInterface();
            decompiler.openProgram(currentProgram);
            DecompileResults results = decompiler.decompileFunction(target, 30, new ConsoleTaskMonitor());
            String decompiledCode = "";
            if (results != null && results.decompileCompleted()) {
                decompiledCode = results.getDecompiledFunction().getC();
            }
            decompiler.dispose();
            json = "{\"name\":\"" + escape(target.getName()) +
                "\",\"entry\":\"" + target.getEntryPoint().toString() +
                "\",\"decompiled\":\"" + escape(decompiledCode) + "\"}";
        }

        FileWriter writer = new FileWriter(outPath);
        writer.write(json);
        writer.close();
    }

    private String escape(String s) {
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
