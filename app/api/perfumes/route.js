import clientPromise from "@/lib/mongodb";
import { NextResponse } from "next/server";

export async function GET() {
  try {
    const client = await clientPromise;
    const db = client.db("themotundebrand");

    // Fetch all perfumes from the "products" collection
    const perfumes = await db
      .collection("products")
      .find({})
      .toArray();

    return NextResponse.json(perfumes, { status: 200 });
  } catch (e) {
    console.error(e);
    return NextResponse.json({ error: "Failed to fetch data" }, { status: 500 });
  }
}