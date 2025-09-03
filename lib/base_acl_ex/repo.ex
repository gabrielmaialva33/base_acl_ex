defmodule BaseAclEx.Repo do
  use Ecto.Repo,
    otp_app: :base_acl_ex,
    adapter: Ecto.Adapters.Postgres

  import Ecto.Query

  @doc """
  Simple pagination function for queries.
  Returns a map with pagination info and results.
  """
  def paginate(query, opts \\ []) do
    page = Keyword.get(opts, :page, 1)
    page_size = Keyword.get(opts, :page_size, 20)

    offset = (page - 1) * page_size

    total_count =
      query
      |> select([_], count())
      |> all()
      |> List.first() || 0

    results =
      query
      |> limit(^page_size)
      |> offset(^offset)
      |> all()

    total_pages = ceil(total_count / page_size)
    has_next = page < total_pages
    has_prev = page > 1

    %{
      entries: results,
      page_number: page,
      page_size: page_size,
      total_entries: total_count,
      total_pages: total_pages,
      has_next_page: has_next,
      has_prev_page: has_prev
    }
  end
end
