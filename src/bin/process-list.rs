use anyhow::Result;
use mitmproxy::processes::active_executables;
use mitmproxy::processes::ICON_CACHE;

fn main() -> Result<()> {

    let mut processes = active_executables()?;
    processes.sort_by_cached_key(|p| (p.is_system, !p.is_visible));

    let mut icon_cache = ICON_CACHE.lock().unwrap();

    println!(r#"<!doctype html><html><body><table>
    <tr>
        <th>Icon</th>
        <th>display_name</th>
        <th>is_visible</th>
        <th>is_system</th>
        <th>executable</th>
    </tr>"#);
    for process in processes {
        let image = if !process.is_system && process.is_visible {
            match icon_cache.get_png(process.executable.clone()) {
                Ok(data) => {
                    let data = data_encoding::BASE64.encode(data);
                    format!("<img src=\"data:image/png;charset=utf-8;base64,{data}\">")
                },
                Err(e) => e.to_string()
            }
        } else {
            "".to_string()
        };
        println!(r#"
        <tr>
            <td>{}</td>
            <td>{}</td>
            <td>{}</td>
            <td>{}</td>
            <td>{}</td>
        </tr>"#,
            image,
            process.display_name,
            process.is_visible,
            process.is_system,
            process.executable.to_string_lossy(),
            );
    }
    println!("</table></body></html>");
    Ok(())
}