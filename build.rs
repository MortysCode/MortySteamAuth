use std::{env, fs::File, io::BufWriter, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=logo.png");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let source = image::open("logo.png").expect("logo.png must be a valid image");
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set"))
        .join("morty-steam-auth.ico");
    let mut icon = ico::IconDir::new(ico::ResourceType::Icon);

    for size in [16, 24, 32, 48, 64, 128, 256] {
        let rgba = source
            .resize_exact(size, size, image::imageops::FilterType::Lanczos3)
            .to_rgba8();
        let image = ico::IconImage::from_rgba_data(size, size, rgba.into_raw());
        icon.add_entry(ico::IconDirEntry::encode(&image).expect("failed to encode icon frame"));
    }

    let file = File::create(&output).expect("failed to create Windows icon");
    icon.write(BufWriter::new(file))
        .expect("failed to write Windows icon");

    winresource::WindowsResource::new()
        .set_icon(output.to_str().expect("icon path must be UTF-8"))
        .set("ProductName", "Morty Steam Auth")
        .set("FileDescription", "Morty Steam Auth")
        .set("LegalCopyright", "Morty Steam Auth")
        .compile()
        .expect("failed to embed Windows resources");
}
